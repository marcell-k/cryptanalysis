use crate::util::{
    ALPHABET, BIGRAMS, TRIGRAMS, chi_square_scoring, count_ngrams, load_or_build_common,
};

pub fn caesar_brute_force_decryption(cipher: String) -> anyhow::Result<String> {
    let common = load_or_build_common()?;

    let mut out: Vec<String> = Vec::with_capacity(26);
    let mut score: Vec<f64> = Vec::with_capacity(26);

    for i in 0..26 {
        let mut s = String::new();
        for ch in cipher.chars() {
            if !ch.is_alphabetic() {
                s.push(ch);
                continue;
            } else {
                let mut index = ALPHABET.iter().position(|c| c == &ch).unwrap();
                index = (index + i) % 26;
                let new_ch = ALPHABET[index];
                s.push(new_ch);
            }
        }
        out.push(s.clone());

        let chi = chi_square_scoring(&s, &common);
        let bi = count_ngrams(&s, &BIGRAMS);
        let tri = count_ngrams(&s, &TRIGRAMS);
        // 10. and 15. arbitrary magic numbers, need to optimize those
        let value = chi - (bi * 10.) - (tri * 15.);
        score.push(value);
    }
    let mut pairs: Vec<(String, f64)> = out.into_iter().zip(score).collect();
    pairs.sort_by(|a, b| a.1.total_cmp(&b.1));
    for (s, v) in pairs.iter().take(5) {
        println!("{} - {:.2}", s, v);
    }

    Ok(pairs[0].0.clone())
}

// for each character `(c[i] + k[i] + 26) % 26 == m[i]`
pub fn viginere_decrpytion(cipher: String, key: String) -> anyhow::Result<String> {
    assert_eq!(cipher.len(), key.len());

    let mut out = String::with_capacity(cipher.len());

    for (ch, kch) in cipher.chars().zip(key.chars()) {
        if ALPHABET.contains(&ch) {
            let cipher_idx = ALPHABET.iter().position(|c| c == &ch).unwrap();
            let key_idx = ALPHABET.iter().position(|c| c == &kch).unwrap();
            let idx = (cipher_idx + key_idx + 26) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Decrypted message: {}, using Viginere", out);

    Ok(out)
}
