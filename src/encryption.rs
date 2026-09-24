use crate::ALPHABET;

pub fn affine_cipher_encryption(message: String) -> anyhow::Result<()> {
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
    println!("Encoded message: {}", out);

    Ok(())
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
