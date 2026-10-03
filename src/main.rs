#![allow(unused_imports)]
#![allow(unused_variables)]

//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::{
    Result, affine_decrypt, affine_encrypt, alberti_decrypt, alberti_encrypt, caesar_crack,
    caesar_encrypt, des_decrypt, des_encrypt, index_of_coincidence, is_bijective_mod26,
    otp_decrypt, otp_encrypt, scytale_decrypt, scytale_encrypt, tdes_decrypt, tdes_encrypt,
    vigenere_crack, vigenere_decrypt, vigenere_encrypt,
};

fn main() -> Result<()> {
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
    // let encoded_message = scytale_encrypt(text.clone(), 3)?;
    // let decoded_message = scytale_decrypt(encoded_message.clone())?;
    // println!("{}", decoded_message);
    //
    // // --- Caesar ---
    // let encoded = caesar_encrypt(text.clone(), 1)?;
    // let (msg, _, caesar_key) = caesar_crack(encoded)?;
    // println!("{} - {}", msg, caesar_key);
    //
    // // --- Alberti ---
    // let encoded_message = alberti_encrypt(text.clone(), 'T', 2)?;
    // let decoded_message = alberti_decrypt(encoded_message.clone())?;
    // println!("{}", decoded_message);
    //
    // // --- Affine ---
    // let encoded_message = affine_encrypt(text.clone(), 7, 2)?;
    // let decoded_message = affine_decrypt(encoded_message)?;
    //
    // // --- Vigenere ---
    // let encoded_message = vigenere_encrypt(text.clone(), key.clone())?;
    // let decoded_message = vigenere_crack(encoded_message)?;
    //
    // // --- One-time Pad ---
    // let key = String::from(
    //     "BTSERE Y,PM AEATNNI,DE  NABTNE D T SILILOLLVE ENTRTHS,E!   TLHHAEASATTR . Y MOREUO  MFMAOANRYS  ,MH YEC AOCRUA:NUX",
    // );
    // let encoded_message = otp_encrypt(text.clone(), key.clone())?;
    // let decoded_message = otp_decrypt(encoded_message, key.clone())?;

    // // --- DES ---
    // let key = String::from("133457799BBCDFF1");
    // let encoded_message = des_encrypt(text.clone(), key.clone())?;
    // let decoded_message = des_decrypt(encoded_message, key.clone())?;

    // --- Triple-DES ---
    let key = String::from("133457799BBCDFF10E329232EA6D0D73FEDCBA9876543210");
    let encoded_message = tdes_encrypt(text.clone(), key.clone())?;
    let decoded_message = tdes_decrypt(encoded_message, key.clone())?;
    assert_eq!(text, decoded_message);
    Ok(())
}
