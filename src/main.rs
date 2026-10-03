#![allow(unused_imports)]
#![allow(unused_variables)]

//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::{
    affine_decrypt, affine_encrypt, alberti_encrypt, caesar_crack, caesar_encrypt, des_decrypt,
    des_encrypt, index_of_coincidence, is_bijective_mod26, otp_decrypt, otp_encrypt,
    scytale_decrypt, scytale_encrypt, vigenere_crack, vigenere_decrypt, vigenere_encrypt,
};

fn main() {
    let text = String::from(
"Be patient till the last. Romans, countrymen, and lovers! hear me for my cause, and be silent, that you may hear:"
    )
    .to_uppercase();
    let cipher = String::from(
        "BTSERE Y,PM AEATNNI,DE  NABTNE D T SILILOLLVE ENTRTHS,E!   TLHHAEASATTR . Y MOREUO  MFMAOANRYS  ,MH YEC AOCRUA:NUX",
    );
    let key = String::from("kalsl").to_uppercase();

    println!("{:<17}: {}", "Message", text);
    println!("{:<17}: {}", "Cipher", cipher);
    let ic = index_of_coincidence(&cipher);
    println!("Index of coincidence: {:.4}", ic);

    // // --- Scytale ---
    // let encoded_message = scytale_encrypt(text.clone(), 3).unwrap();
    // let decoded_message = scytale_decrypt(encoded_message.clone()).unwrap();
    // println!("{}", decoded_message);
    //
    // // --- Caesar ---
    // let encoded = caesar_encrypt(text.clone(), 1).unwrap();
    // let (msg, _, caesar_key) = caesar_crack(encoded).unwrap();
    // println!("{} - {}", msg, caesar_key);

    // --- Alberti ---
    // let encoded_message = alberti_encrypt(text.clone(), 't', 2).unwrap();
    // let decoded_message = affine_decrypt(encoded_message.clone()).unwrap();
    // println!("{}", decoded_message);
    //
    // // --- Affine ---
    // let encoded_message = affine_encrypt(text.clone(), 7, 2).unwrap();
    // let decoded_message = affine_decrypt(cipher.clone()).unwrap();
    //
    // // --- Vigenere ---
    // let encoded_message = vigenere_encrypt(text.clone(), key.clone()).unwrap();
    // let decoded_message = vigenere_crack(encoded_message).unwrap();

    // --- One-time Pad ---
    // let key = String::from(
    //     "BTSERE Y,PM AEATNNI,DE  NABTNE D T SILILOLLVE ENTRTHS,E!   TLHHAEASATTR . Y MOREUO  MFMAOANRYS  ,MH YEC AOCRUA:NUX",
    // );
    // let encoded_message = otp_encrypt(text.clone(), key.clone()).unwrap();
    // let decoded_message = otp_decrypt(encoded_message, key.clone()).unwrap();

    // --- DES ---
    let key = String::from("133457799BBCDFF1");
    let encoded_message = des_encrypt(text.clone(), key.clone()).unwrap();
    let decoded_message = des_decrypt(encoded_message, key.clone()).unwrap();
}
