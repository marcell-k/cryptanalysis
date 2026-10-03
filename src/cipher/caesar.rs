use crate::Result;

use crate::util::{
    ALPHABET, BIGRAMS, TRIGRAMS, chi_square_score, count_ngrams, english_frequencies,
};

pub fn caesar_encrypt(message: String, key: usize) -> Result<String> {
    let mut out = String::with_capacity(message.len());

    for ch in message.chars() {
        if ALPHABET.contains(&ch) {
            let mut idx = ALPHABET.iter().position(|c| *c == ch).unwrap();
            idx = (idx + key) % 26;
            out.push(ALPHABET[idx]);
        } else {
            out.push(ch);
        }
    }
    println!("Encoded message  : {}, using caesar", out);
    Ok(out)
}

pub fn caesar_crack(cipher: String) -> Result<(String, f64, usize)> {
    let common = english_frequencies();

    let mut out: Vec<String> = Vec::with_capacity(26);
    let mut score: Vec<f64> = Vec::with_capacity(26);
    let mut rotation = 0;
    let mut rotation_value = f64::MAX;

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

        let chi = chi_square_score(&s, common);
        let bi = count_ngrams(&s, &BIGRAMS);
        let tri = count_ngrams(&s, &TRIGRAMS);
        // 10. and 15. arbitrary magic numbers, need to optimize those
        let value = chi - (bi * 10.) - (tri * 15.);
        score.push(value);
        if value < rotation_value {
            rotation_value = value;
            rotation = i;
        }
    }
    let mut pairs: Vec<(String, f64)> = out.into_iter().zip(score).collect();
    pairs.sort_by(|a, b| a.1.total_cmp(&b.1));
    // for (s, v) in pairs.iter().take(5) {
    //     println!("{} - {:.2}", s, v);
    // }

    Ok((pairs[0].0.clone(), pairs[0].1, (26 - rotation) % 26))
}

pub fn caesar_crack_by_frequency(cipher: String) -> Result<(String, f64, usize)> {
    let common = english_frequencies();
    let mut best_msg = String::new();
    let mut best_value = f64::MAX;
    let mut best_rotation = 0;

    for i in 0..26 {
        let mut s = String::with_capacity(cipher.len());
        for ch in cipher.chars() {
            if !ch.is_alphabetic() {
                s.push(ch);
                continue;
            }
            let index = ALPHABET.iter().position(|c| c == &ch).unwrap();
            s.push(ALPHABET[(index + i) % 26]);
        }
        let value = chi_square_score(&s, common);
        if value < best_value {
            best_value = value;
            best_rotation = i;
            best_msg = s;
        }
    }
    Ok((best_msg, best_value, (26 - best_rotation) % 26))
}

#[cfg(test)]
mod test {
    use super::caesar_crack;

    #[test]
    fn test_caesar_crack() {
        let cipher = String::from("MEET AT 5PM SHARP!");
        let _ = caesar_crack(cipher);
    }
}
