#![allow(unused_imports)]
#![allow(unused_variables)]

//! Frequency analysis
//! is the study of how often letters, symbols, pairs of letters, triples of letters,
//! and other patterns occur in a ciphertext. It does not necessarily require the key. It does not always
//! require knowing the exact cipher. It begins with a simpler question: **what does this ciphertext do often**?

use freq_analysis::{
    affine_cipher_encryption, caesar_brute_force_decryption, ceaser_encryption,
    index_of_coincidence, is_bijective_mod26, vigenere_cipher_encryption, vigenere_decrpytion,
    vigenere_decrpytion_brute_force,
};

fn main() {
    let cipher = String::from(
"Be patient till the last. Romans, countrymen, and lovers! hear me for my cause, and be silent, that you may hear: believe me for mine honour, and have respect to mine honour, that you may believe: censure me in your wisdom, and awake your senses, that you may the better judge. If there be any in this assembly, any dear friend of Caesar's, to him I say, that Brutus' love to Caesar was no less than his. If then that friend demand why Brutus rose against Caesar, this is my answer: —Not that I loved Caesar less, but that I loved Rome more. Had you rather Caesar were living and die all slaves, than that Caesar were dead, to live all free men? As Caesar loved me, I weep for him; as he was fortunate, I rejoice at it; as he was valiant, I honour him: but, as he was ambitious, I slew him. There is tears for his love; joy for his fortune; honour for his valour; and death for his ambition. Who is here so base that would be a bondman? If any, speak; for him have I offended. Who is here so rude that would not be a Roman? If any, speak; for him have I offended. Who is here so vile that will not love his country? If any, speak; for him have I offended. I pause for a reply. Then none have I offended. I have done no more to Caesar than you shall do to Brutus. The question of his death is enrolled in the Capitol; his glory not extenuated, wherein he was worthy, nor his offences enforced, for which he suffered death. Here comes his body, mourned by Mark Antony: who, though he had no hand in his death, shall receive the benefit of his dying, a place in the commonwealth; as which of you shall not? With this I depart,—that, as I slew my best lover for the good of Rome, I have the same dagger for myself, when it shall please my country to need my death."
    )
    .to_uppercase();
    let key = String::from("kalsl").to_uppercase();

    let ic = index_of_coincidence(&cipher);
    println!("Index of coincidence: {:.4}", ic);
    println!("{:<17}: {}", "Cipher", cipher);

    // --- Caesar ---
    // let encoded = ceaser_encryption(cipher, 1).unwrap();
    // let (msg, key) = caesar_brute_force_decryption(encoded).unwrap();
    // println!("{} - {}", msg, key);

    // --- Affine ---
    // affine_cipher_encryption(cipher.clone());

    // --- Vigenere ---
    let encoded_message = vigenere_cipher_encryption(cipher.clone(), key.clone()).unwrap();
    let decoded_message = vigenere_decrpytion_brute_force(encoded_message).unwrap();
    println!("{}", decoded_message)
}
