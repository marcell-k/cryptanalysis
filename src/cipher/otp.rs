use std::ops::BitXor;

use crate::error::{CipherError, Result};
pub fn otp_encrypt(message: String, key: String) -> Result<String> {
    let message_bytes = message.as_bytes();
    let key_bytes = key.as_bytes();

    if key_bytes.len() < message_bytes.len() {
        return Err(CipherError::KeyTooShort {
            key: key_bytes.len(),
            message: message_bytes.len(),
        });
    }

    let out: Vec<u8> = message_bytes
        .iter()
        .zip(key_bytes)
        .map(|(m, k)| {
            let v = m.bitxor(k);
            // println!("m:{:08b}, k:{:08b}, m^k:{:08b}", m, k, v);
            v
        })
        .collect();

    let hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Encoded message  : {}, using otp", hex);
    Ok(hex)
}
pub fn otp_decrypt(cipher: String, key: String) -> Result<String> {
    // checked up front so the slicing below can't panic on odd length / non-ASCII
    if !cipher.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CipherError::InvalidCiphertext("non-hex character"));
    }
    if !cipher.len().is_multiple_of(2) {
        return Err(CipherError::InvalidCiphertext("odd number of hex digits"));
    }

    let cipher_bytes: Vec<u8> = (0..cipher.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cipher[i..i + 2], 16).unwrap()) // validated above
        .collect();
    let key_bytes = key.as_bytes();
    if key_bytes.len() < cipher_bytes.len() {
        return Err(CipherError::KeyTooShort {
            key: key_bytes.len(),
            message: cipher_bytes.len(),
        });
    }
    let plain: Vec<u8> = cipher_bytes
        .iter()
        .zip(key_bytes)
        .map(|(c, k)| c ^ k)
        .collect();
    let message = String::from_utf8(plain)?;

    println!("Decrypted message: {}, using otp", message);
    Ok(message)
}

#[cfg(test)]
mod test {
    use crate::{CipherError, otp_decrypt, otp_encrypt};

    #[test]
    fn test_otp_encrypt() {
        let message = String::from("ATTACK NOW");
        let key = String::from("FKADEEGLÉK");
        assert_eq!("071f1505060e67028cde", otp_encrypt(message, key).unwrap());
    }

    #[test]
    fn test_otp_roundtrip() {
        let message = String::from("ATTACK NOW");
        let key = String::from("FKADEEGLÉK");
        let cipher = otp_encrypt(message.clone(), key.clone()).unwrap();
        assert_eq!(message, otp_decrypt(cipher, key).unwrap())
    }
    #[test]
    fn test_otp_key_too_short() {
        let err = otp_encrypt("ATTACK NOW".into(), "SHORT".into()).unwrap_err();
        assert!(matches!(
            err,
            CipherError::KeyTooShort {
                key: 5,
                message: 10
            }
        ));

        let err = otp_decrypt("071f1505060e67028cde".into(), "SHORT".into()).unwrap_err();
        assert!(matches!(
            err,
            CipherError::KeyTooShort {
                key: 5,
                message: 10
            }
        ));
    }

    #[test]
    fn test_otp_decrypt_invalid_ciphertext() {
        // odd length (previously panicked on slice)
        let err = otp_decrypt("071".into(), "KEYWORD".into()).unwrap_err();
        assert!(matches!(err, CipherError::InvalidCiphertext(_)));

        // non-hex / non-ASCII (previously panicked or accepted "+1")
        for bad in ["zz", "+1", "é1"] {
            let err = otp_decrypt(bad.into(), "KEYWORD".into()).unwrap_err();
            assert!(matches!(err, CipherError::InvalidCiphertext(_)));
        }
    }

    #[test]
    fn test_otp_decrypt_invalid_utf8() {
        // 0xFF ^ 0x00 = 0xFF, not valid UTF-8
        let err = otp_decrypt("ff".into(), "\0".into()).unwrap_err();
        assert!(matches!(err, CipherError::Utf8(_)));
    }
}
