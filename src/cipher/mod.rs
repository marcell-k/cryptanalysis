pub mod affine;
pub mod alberti;
pub mod bellaso;
pub mod caesar;
pub mod otp;
pub mod scytale;
pub mod vigenere;

pub use affine::{affine_decrypt, affine_encrypt};
pub use alberti::{alberti_decrypt, alberti_encrypt};
pub use bellaso::{bellaso_crack, bellaso_decrypt, bellaso_encrypt};
pub use caesar::{caesar_crack, caesar_encrypt};
pub use otp::{otp_decrypt, otp_encrypt};
pub use scytale::{scytale_decrypt, scytale_encrypt};
pub use vigenere::{
    key_lengths, possible_key_lengths, vigenere_crack, vigenere_decrypt, vigenere_encrypt,
};
