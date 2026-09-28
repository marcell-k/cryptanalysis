use std::ops::BitXor;

use anyhow::bail;

pub fn otp_encrypt(message: String, key: String) -> anyhow::Result<String> {
    let message_bytes = message.as_bytes();
    let key_bytes = key.as_bytes();

    if key_bytes.len() < message_bytes.len() {
        bail!(
            "key too short: {}, bytes for a {} byte message",
            key_bytes.len(),
            message_bytes.len()
        )
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
pub fn otp_decrypt(cipher: String, key: String) -> anyhow::Result<String> {
    let cipher_bytes: Vec<u8> = (0..cipher.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cipher[i..i + 2], 16))
        .collect::<Result<_, _>>()?;
    let key_bytes = key.as_bytes();
    if key_bytes.len() < cipher_bytes.len() {
        bail!(
            "key too short: {}, bytes for a {} byte message",
            key_bytes.len(),
            cipher.len()
        )
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
    use crate::{otp_decrypt, otp_encrypt};

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
}
