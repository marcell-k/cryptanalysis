use std::string::FromUtf8Error;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CipherError {
    // --- shared ---
    #[error("decrypted bytes are not valid UTF-8")]
    Utf8(#[from] FromUtf8Error),

    // --- OTP ---
    #[error("key too short: {key} bytes for a {message} byte message")]
    KeyTooShort { key: usize, message: usize },

    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(&'static str),

    // --- DES ---
    #[error("DES key must be 16 hex chars or 8 ASCII chars, got {key_length} chars")]
    DesKeyLength { key_length: usize },

    #[error("DES key must be ASCII or 16 hex chars")]
    DesKeyNotAscii,

    #[error("DES ciphertext must be hex, a non-zero multiple of 16 chars")]
    DesInvalidCipher,

    #[error("invalid padding (wrong key?)")]
    InvalidPadding,
}

pub type Result<T> = std::result::Result<T, CipherError>;
