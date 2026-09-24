use crate::util::{ALPHABET, count_chars};
mod util;
pub use util::is_bijective_mod26;
mod decryption;
mod encryption;
pub use decryption::caesar_brute_force_decryption;
pub use encryption::affine_cipher_encryption;

// IC range 0.038 (random) to 0.067 (English). Close to 0.067 = valid English or mono-alphabetic cipher.
pub fn index_of_coincidence(cipher: &str) -> f64 {
    let counts = count_chars(cipher);
    let n: u64 = counts.values().map(|&c| c as u64).sum();
    let numerator: u64 = counts.values().map(|&c| (c as u64) * (c as u64 - 1)).sum();
    let n = n as f64;
    numerator as f64 / (n * (n - 1.))
}
