//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::{ALPHABET, chi_square_scoring, load_or_build_common};

fn main() -> anyhow::Result<()> {
    let cipher = String::from("WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ");
    let common = load_or_build_common()?;

    let mut out: Vec<String> = Vec::with_capacity(26);
    let mut score: Vec<f64> = Vec::with_capacity(26);

    for i in 0..26 {
        let mut s = String::new();
        for ch in cipher.chars() {
            if ch == ' ' {
                s.push(' ');
                continue;
            } else {
                let mut index = ALPHABET.iter().position(|c| c == &ch).unwrap();
                index = (index + i) % 26;
                let new_ch = ALPHABET[index];
                s.push(new_ch);
            }
        }
        out.push(s.clone());
        score.push(chi_square_scoring(&s, &common));
    }
    let mut pairs: Vec<(String, f64)> = out.into_iter().zip(score).collect();
    pairs.sort_by(|a, b| a.1.total_cmp(&b.1));
    for (s, v) in pairs.iter().take(5) {
        println!("{} - {:.2}", s, v);
    }

    Ok(())
}
