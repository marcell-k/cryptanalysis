mod analysis;
mod cipher;
mod error;
mod util;

pub use analysis::{index_of_coincidence, is_bijective_mod26};
pub use cipher::{
    affine_decrypt, affine_encrypt, alberti_decrypt, alberti_encrypt, bellaso_crack,
    bellaso_decrypt, bellaso_encrypt, caesar_crack, caesar_encrypt, des_decrypt, des_encrypt,
    key_lengths, otp_decrypt, otp_encrypt, possible_key_lengths, scytale_decrypt, scytale_encrypt,
    tdes_decrypt, tdes_encrypt, vigenere_crack, vigenere_decrypt, vigenere_encrypt,
};
pub use error::{CipherError, Result};
