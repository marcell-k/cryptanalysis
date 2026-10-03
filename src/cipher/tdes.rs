use super::des::{Mode, crypt_block, parse_key, subkeys};
use crate::{
    CipherError, Result,
    cipher::des::{pkcs7_pad, pkcs7_unpad},
};

type Schedules = [[u64; 16]; 3];

fn parse_tdes_key(key: &str) -> Result<Schedules> {
    // checked first so the byte slicing below can't panic on non-ASCII
    if !key.is_ascii() {
        return Err(CipherError::DesKeyNotAscii);
    }
    let parts: [&str; 3] = match key.len() {
        48 => [&key[0..16], &key[16..32], &key[32..48]],
        32 => [&key[0..16], &key[16..32], &key[0..16]],
        24 => [&key[0..8], &key[8..16], &key[16..24]],
        n => return Err(CipherError::DesKeyLength { key_length: n }),
    };
    Ok([
        subkeys(parse_key(parts[0])?),
        subkeys(parse_key(parts[1])?),
        subkeys(parse_key(parts[2])?),
    ])
}

fn tdes_encrypt_block(block: u64, ks: &Schedules) -> u64 {
    let b = crypt_block(block, &ks[0], Mode::Encrypt);
    let b = crypt_block(b, &ks[1], Mode::Decrypt);
    crypt_block(b, &ks[2], Mode::Encrypt)
}

fn tdes_decrypt_block(block: u64, ks: &Schedules) -> u64 {
    let b = crypt_block(block, &ks[2], Mode::Decrypt);
    let b = crypt_block(b, &ks[1], Mode::Encrypt);
    crypt_block(b, &ks[0], Mode::Decrypt)
}

pub fn tdes_encrypt(message: String, key: String) -> Result<String> {
    let ks = parse_tdes_key(&key)?;

    let bytes = pkcs7_pad(message.into_bytes());

    let hex: String = bytes
        .chunks(8)
        .map(|chunk| {
            let block = u64::from_be_bytes(chunk.try_into().unwrap()); // chunks of 8
            format!("{:016X}", tdes_encrypt_block(block, &ks))
        })
        .collect();

    println!("Encoded message  : {}, using 3des", hex);
    Ok(hex)
}

pub fn tdes_decrypt(cipher: String, key: String) -> Result<String> {
    let ks = parse_tdes_key(&key)?;
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
        bytes.extend(tdes_decrypt_block(block, &ks).to_be_bytes());
    }

    let bytes = pkcs7_unpad(bytes)?;

    let message = String::from_utf8(bytes)?;
    println!("Decrypted message: {}, using 3des", message);
    Ok(message)
}

#[cfg(test)]
mod test {
    use super::*;

    const K1: &str = "133457799BBCDFF1";
    const K2: &str = "0E329232EA6D0D73";
    const K3: &str = "FEDCBA9876543210";

    #[test]
    fn test_three_key_roundtrip() {
        let key = format!("{K1}{K2}{K3}");
        let msg = "Be patient till the last. Romans, countrymen, and lovers!";
        let c = tdes_encrypt(msg.into(), key.clone()).unwrap();
        assert_eq!(tdes_decrypt(c, key).unwrap(), msg);
    }

    #[test]
    fn test_two_key_roundtrip() {
        let key = format!("{K1}{K2}");
        let c = tdes_encrypt("two key variant".into(), key.clone()).unwrap();
        assert_eq!(tdes_decrypt(c, key).unwrap(), "two key variant");
    }

    #[test]
    fn test_two_key_equals_three_key_with_k3_eq_k1() {
        let two = format!("{K1}{K2}");
        let three = format!("{K1}{K2}{K1}");
        assert_eq!(
            tdes_encrypt("same".into(), two).unwrap(),
            tdes_encrypt("same".into(), three).unwrap()
        );
    }

    #[test]
    fn test_ascii_key_roundtrip() {
        let key = "ABCDEFGHIJKLMNOPQRSTUVWX".to_string();
        let c = tdes_encrypt("ascii key".into(), key.clone()).unwrap();
        assert_eq!(tdes_decrypt(c, key).unwrap(), "ascii key");
    }

    #[test]
    fn test_single_des_compatibility() {
        // K1 = K2 = K3 collapses EDE to single DES
        let ks = parse_tdes_key(&format!("{K1}{K1}{K1}")).unwrap();
        assert_eq!(
            tdes_encrypt_block(0x0123456789ABCDEF, &ks),
            0x85E813540F0AB405
        );
        assert_eq!(
            tdes_decrypt_block(0x85E813540F0AB405, &ks),
            0x0123456789ABCDEF
        );
    }

    #[test]
    fn test_edge_cases() {
        let key = format!("{K1}{K2}{K3}");
        for msg in ["", "1234567", "12345678", "héllo wörld ✓"] {
            let c = tdes_encrypt(msg.into(), key.clone()).unwrap();
            assert_eq!(tdes_decrypt(c, key.clone()).unwrap(), msg);
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let c = tdes_encrypt("secret message".into(), format!("{K1}{K2}{K3}")).unwrap();
        let err = tdes_decrypt(c, format!("{K3}{K2}{K1}")).unwrap_err();
        assert!(matches!(
            err,
            CipherError::InvalidPadding | CipherError::Utf8(_)
        ));
    }

    #[test]
    fn test_invalid_inputs() {
        assert!(matches!(
            tdes_encrypt("x".into(), "short".into()),
            Err(CipherError::DesKeyLength { key_length: 5 })
        ));
        assert!(matches!(
            tdes_encrypt("x".into(), "é".repeat(12)),
            Err(CipherError::DesKeyNotAscii)
        ));
        assert!(matches!(
            tdes_encrypt("x".into(), "Z".repeat(48)),
            Err(CipherError::DesKeyNotHex)
        ));
        let key = format!("{K1}{K2}{K3}");
        for bad in ["", "zzzzzzzzzzzzzzzz", "0123"] {
            assert!(matches!(
                tdes_decrypt(bad.into(), key.clone()),
                Err(CipherError::InvalidCiphertext(_))
            ));
        }
    }
}
