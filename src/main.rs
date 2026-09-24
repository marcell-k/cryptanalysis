#![allow(unused_imports)]

//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::{
    affine_cipher_encryption, caesar_brute_force_decryption, index_of_coincidence,
    is_bijective_mod26,
};

fn main() -> anyhow::Result<()> {
    let _cipher = String::from("WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ");
    let cipher = String::from("A rose by any other name would smell as sweet.").to_uppercase();

    let ic = index_of_coincidence(&cipher);
    println!("Index of coincidence: {:.4}", ic);
    // caesar_brute_force_decryption(cipher);

    for a in 721597..721600 {
        let is_true = is_bijective_mod26(|idx| (idx * a + 78) % 26);
        if is_true {
            println!("a={a}")
        }
    }
    affine_cipher_encryption(cipher)
}
