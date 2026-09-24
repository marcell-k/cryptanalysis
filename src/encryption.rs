use crate::ALPHABET;

// for each character: `(w[i] * a + b) % 26`
pub fn affine_cipher_encryption(message: String) -> anyhow::Result<String> {
    let mut out = String::with_capacity(message.len());

    for ch in message.chars() {
        if ALPHABET.contains(&ch) {
            let mut idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
            idx = (idx * 721599 + 19) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Encoded message  : {}, using affine", out);

    Ok(out)
}

// for each character: `(w[i] + k[i]) % 26`
pub fn vigenere_cipher_encryption(message: String, key: String) -> anyhow::Result<String> {
    assert_eq!(message.len(), key.len());

    let mut out = String::with_capacity(message.len());
    for (ch, kch) in message.chars().zip(key.chars()) {
        if ALPHABET.contains(&ch) {
            let idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
            let key_idx = ALPHABET.iter().position(|c| c == &kch).unwrap();
            let idx = (idx + key_idx) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Encoded message  : {}, using Vigenere", out);
    Ok(out)
}

#[cfg(test)]
mod test {
    use crate::decryption::caesar_brute_force_decryption;

    #[test]
    fn test_caesar_brute_force_decryption() {
        let cipher = String::from("MEET AT 5PM SHARP!");
        let _ = caesar_brute_force_decryption(cipher);
    }
}
