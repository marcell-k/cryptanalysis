use crate::util::count_chars;

// IC range 0.038 (random) to 0.067 (English). Close to 0.067 = valid English or mono-alphabetic cipher.
pub fn index_of_coincidence(cipher: &str) -> f64 {
    let counts = count_chars(cipher);
    let n: u64 = counts.values().map(|&c| c as u64).sum();
    let numerator: u64 = counts.values().map(|&c| (c as u64) * (c as u64 - 1)).sum();
    let n = n as f64;
    numerator as f64 / (n * (n - 1.))
}

pub fn is_bijective_mod26(f: impl Fn(usize) -> usize) -> bool {
    let mut seen = [false; 26];

    for idx in 0..26 {
        let out = f(idx) % 26;
        if seen[out] {
            return false;
        }
        seen[out] = true;
    }
    true
}
