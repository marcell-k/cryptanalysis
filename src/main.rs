#![allow(unused_imports)]
#![allow(unused_variables)]

//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::{
    affine_decrypt, affine_encrypt, caesar_crack, caesar_encrypt, index_of_coincidence,
    is_bijective_mod26, vigenere_crack, vigenere_decrypt, vigenere_encrypt,
};

fn main() {
    let text = String::from(
"Be patient till the last. Romans, countrymen, and lovers! hear me for my cause, and be silent, that you may hear:"
    )
    .to_uppercase();
    let cipher = String::from(
        "JE DCFGEPF FGBB FZE BCYF. RWICPY, QWMPFROIEP, CPX BWTERY! ZECR IE LWR IO QCMYE, CPX JE YGBEPF, FZCF OWM ICO ZECR:",
    );
    let key = String::from("kalsl").to_uppercase();

    let ic = index_of_coincidence(&cipher);
    println!("Index of coincidence: {:.4}", ic);
    println!("{:<17}: {}", "Cipher", cipher);

    // --- Caesar ---
    // let encoded = caesar_encrypt(cipher, 1).unwrap();
    // let (msg, _, key) = caesar_crack(encoded).unwrap();
    // println!("{} - {}", msg, key);

    // --- Affine ---
    let encoded_message = affine_encrypt(text.clone(), 7, 2).unwrap();
    let decoded_message = affine_decrypt(cipher.clone()).unwrap();

    // --- Vigenere ---
    // let encoded_message = vigenere_encrypt(cipher.clone(), key.clone()).unwrap();
    // let decoded_message = vigenere_crack(encoded_message).unwrap();
    // println!("{}", decoded_message)
}
