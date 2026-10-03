// TODO: ECB
use crate::{CipherError, Result};

fn permute(input: u64, in_bits: u32, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        let bit = (input >> (in_bits - pos as u32)) & 1;
        out = (out << 1) | bit;
    }
    out
}

fn rot28(x: u32, n: u32) -> u32 {
    ((x << n) | (x >> (28 - n))) & 0x0FFF_FFFF
}

/// Step 1: 64-bit key -> sixteen 48-bit subkeys (stored in the low 48 bits of a u64).
pub(crate) fn subkeys(key: u64) -> [u64; 16] {
    let k_plus = permute(key, 64, &PC_1);
    let mut c = (k_plus >> 28) as u32 & 0x0FFF_FFFF;
    let mut d = k_plus as u32 & 0x0FFF_FFFF;

    let mut keys = [0u64; 16];
    for (i, &shift) in SHIFTS.iter().enumerate() {
        c = rot28(c, shift);
        d = rot28(d, shift);
        let cd = ((c as u64) << 28) | d as u64;
        keys[i] = permute(cd, 56, &PC_2);
    }
    keys
}
/// The round function f(R, K): expand, XOR key, S-boxes, permute.
fn feistel(r: u32, k: u64) -> u32 {
    let x = permute(r as u64, 32, &E) ^ k; // 48 bits

    let mut out = 0u32;
    for (i, sbox) in SBOX.iter().enumerate() {
        // take 6 bit group, `0x3F = 0b00111111`
        let b = ((x >> (42 - 6 * i)) & 0x3F) as usize;
        let row = ((b & 0b100000) >> 4) | (b & 1); // outer bits
        let col = (b >> 1) & 0xF; // middle 4 bits 0xF = 0b
        out = (out << 4) | sbox[row * 16 + col] as u32;
    }
    permute(out as u64, 32, &P) as u32
}

pub(crate) enum Mode {
    Encrypt,
    Decrypt,
}
/// Encrypt (or decrypt) one 64-bit block.
pub(crate) fn crypt_block(block: u64, keys: &[u64; 16], mode: Mode) -> u64 {
    let ip = permute(block, 64, &IP);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;

    for round in 0..16 {
        let k = match mode {
            Mode::Decrypt => keys[15 - round],
            Mode::Encrypt => keys[round],
        };
        (l, r) = (r, l ^ feistel(r, k));
    }

    let pre = ((r as u64) << 32) | l as u64;
    permute(pre, 64, &IP_INV)
}

pub(crate) fn parse_key(key: &str) -> Result<u64> {
    if !key.is_ascii() {
        return Err(CipherError::DesKeyNotAscii);
    }
    match key.len() {
        16 if key.chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(u64::from_str_radix(key, 16).unwrap()) // validated above
        }
        16 => Err(CipherError::DesKeyNotHex),
        8 => Ok(u64::from_be_bytes(key.as_bytes().try_into().unwrap())), // len == 8 checked
        n => Err(CipherError::DesKeyLength { key_length: n }),
    }
}

pub fn des_encrypt(message: String, key: String) -> Result<String> {
    let keys = subkeys(parse_key(&key)?);

    let mut bytes = message.into_bytes();
    // TODO: Padding validation use PKCS#7
    let pad_len = 8 - (bytes.len() % 8);
    bytes.extend(std::iter::repeat_n(pad_len as u8, pad_len));

    let hex: String = bytes
        .chunks(8)
        .map(|chunk| {
            let block = u64::from_be_bytes(chunk.try_into().unwrap());

            format!("{:016X}", crypt_block(block, &keys, Mode::Encrypt))
        })
        .collect();

    println!("Encoded message  : {}, using des", hex);
    Ok(hex)
}

pub fn des_decrypt(cipher: String, key: String) -> Result<String> {
    let keys = subkeys(parse_key(&key)?);
    if cipher.is_empty() {
        return Err(CipherError::InvalidCiphertext("empty ciphertext"));
    }
    // hex check first so the slicing below can't panic on non-ASCII
    if !cipher.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CipherError::InvalidCiphertext("non-hex character"));
    }
    if !cipher.len().is_multiple_of(16) {
        return Err(CipherError::InvalidCiphertext(
            "length must be a multiple of 16 hex digits",
        ));
    }

    let mut bytes = Vec::with_capacity(cipher.len() / 2);
    for i in (0..cipher.len()).step_by(16) {
        let block = u64::from_str_radix(&cipher[i..i + 16], 16).unwrap(); // validated above
        bytes.extend(crypt_block(block, &keys, Mode::Decrypt).to_be_bytes());
    }

    let pad_len = *bytes.last().unwrap() as usize; // non-empty guaranteed
    if !(1..=8).contains(&pad_len)
        || !bytes[bytes.len() - pad_len..]
            .iter()
            .all(|&b| b as usize == pad_len)
    {
        return Err(CipherError::InvalidPadding);
    }
    bytes.truncate(bytes.len() - pad_len);

    let message = String::from_utf8(bytes)?;
    println!("Decrypted message: {}, using des", message);
    Ok(message)
}

// --- tables (1-indexed, bit 1 = most significant bit) ---

const PC_1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC_2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const IP_INV: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

// Each S-box: 4 rows x 16 columns
const SBOX: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, //
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, //
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, //
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, //
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, //
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, //
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, //
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, //
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, //
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, //
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, //
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, //
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, //
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, //
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, //
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, //
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, //
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, //
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, //
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, //
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, //
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, //
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, //
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, //
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

fn bin_groups(x: u64, bits: usize, group: usize) -> String {
    let s = format!("{:0width$b}", x, width = bits);
    s.as_bytes()
        .chunks(group)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: u64 = 0x133457799BBCDFF1;

    #[test]
    fn test_first_subkey() {
        // K1 = 000110 110000 001011 101111 111111 000111 000001 110010
        assert_eq!(subkeys(KEY)[0], 0x1B02EFFC7072);
    }

    #[test]
    fn test_initial_permutation() {
        let ip = permute(0x0123456789ABCDEF, 64, &IP);
        assert_eq!(ip >> 32, 0xCC00CCFF); // L0
        assert_eq!(ip & 0xFFFF_FFFF, 0xF0AAF0AA); // R0
    }

    #[test]
    fn test_expansion() {
        // E(R0) = 011110 100001 010101 010101 011110 100001 010101 010101
        assert_eq!(permute(0xF0AAF0AA, 32, &E), 0x7A15557A1555);
    }

    #[test]
    fn test_known_block() {
        let keys = subkeys(KEY);
        assert_eq!(
            crypt_block(0x0123456789ABCDEF, &keys, Mode::Encrypt),
            0x85E813540F0AB405
        );
        assert_eq!(
            crypt_block(0x85E813540F0AB405, &keys, Mode::Decrypt),
            0x0123456789ABCDEF
        );
    }

    #[test]
    fn test_roundtrip() {
        let key = "133457799BBCDFF1".to_string();
        let c = des_encrypt("Be patient till the last.".into(), key.clone()).unwrap();
        assert_eq!(des_decrypt(c, key).unwrap(), "Be patient till the last.");
    }
    #[test]
    fn test_sbox_example() {
        // S1(011011) = 0101: row 01, column 1101 -> 5
        let b = 0b011011usize;
        let row = ((b & 0b100000) >> 4) | (b & 1);
        let col = (b >> 1) & 0xF;
        assert_eq!(SBOX[0][row * 16 + col], 5);
    }

    #[test]
    fn test_round_one() {
        let keys = subkeys(KEY);
        let f = feistel(0xF0AAF0AA, keys[0]);
        assert_eq!(f, 0x234AA9BB); // f(R0, K1)
        assert_eq!(0xCC00CCFF ^ f, 0xEF4A6544); // R1 = L0 ^ f
    }

    #[test]
    fn test_article_first_example() {
        // "8787878787878787" with key 0E329232EA6D0D73 -> all zeros
        let keys = subkeys(0x0E329232EA6D0D73);
        assert_eq!(crypt_block(0x8787878787878787, &keys, Mode::Encrypt), 0);
    }

    #[test]
    fn test_article_message_blocks() {
        let keys = subkeys(0x0E329232EA6D0D73);
        // article pads with zero bytes (not PKCS#7): 38 bytes + 2 zeros = 40
        let msg = b"Your lips are smoother than vaseline\r\n\0\0";
        let expected: [u64; 5] = [
            0xC0999FDDE378D7ED,
            0x727DA00BCA5A84EE,
            0x47F269A4D6438190,
            0xD9D52F78F5358499, // article prints 9DD5..., a transposed-digit typo
            0x828AC9B453E0E653,
        ];
        for (chunk, want) in msg.chunks(8).zip(expected) {
            let block = u64::from_be_bytes(chunk.try_into().unwrap());
            assert_eq!(crypt_block(block, &keys, Mode::Encrypt), want);
        }
    }
    #[test]
    fn test_edge_cases() {
        let key = "133457799BBCDFF1".to_string();
        for msg in ["", "1234567", "12345678", "héllo wörld ✓"] {
            let c = des_encrypt(msg.into(), key.clone()).unwrap();
            assert_eq!(des_decrypt(c, key.clone()).unwrap(), msg);
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let c = des_encrypt("secret message".into(), "133457799BBCDFF1".into()).unwrap();
        let err = des_decrypt(c, "0E329232EA6D0D73".into()).unwrap_err();
        assert!(matches!(
            err,
            CipherError::InvalidPadding | CipherError::Utf8(_)
        ));
    }
    #[test]
    fn test_invalid_inputs() {
        assert!(matches!(
            des_encrypt("x".into(), "short".into()),
            Err(CipherError::DesKeyLength { key_length: 5 })
        ));
        assert!(matches!(
            des_encrypt("x".into(), "ééé".into()),
            Err(CipherError::DesKeyNotAscii)
        ));
        for bad in ["", "zzzzzzzzzzzzzzzz", "0123"] {
            assert!(matches!(
                des_decrypt(bad.into(), "12345678".into()),
                Err(CipherError::InvalidCiphertext(_))
            ));
            assert!(matches!(
                des_encrypt("x".into(), "ZZZZZZZZZZZZZZZZ".into()),
                Err(CipherError::DesKeyNotHex)
            ));
        }
    }
}
