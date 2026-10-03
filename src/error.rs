use std::string::FromUtf8Error;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CipherError {
    // --- shared ---
    #[error("decrypted bytes are not valid UTF-8")]
    Utf8(#[from] FromUtf8Error),

    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(&'static str),

    #[error("invalid padding (wrong key?)")]
    InvalidPadding,

    // --- keys / parameters ---
    #[error("key must not be empty")]
    EmptyKey,

    #[error("invalid key character {0:?}")]
    InvalidKeyChar(char),

    #[error("{0} must be greater than zero")]
    ZeroParameter(&'static str),

    // --- OTP ---
    #[error("key too short: {key} bytes for a {message} byte message")]
    KeyTooShort { key: usize, message: usize },

    // --- DES ---
    #[error("DES key must be 16 hex digits or 8 ASCII bytes, got {key_length} bytes")]
    DesKeyLength { key_length: usize },

    #[error("DES key must be ASCII")]
    DesKeyNotAscii,

    #[error("a 16-character DES key must contain only hex digits")]
    DesKeyNotHex,
}

pub type Result<T, E = CipherError> = std::result::Result<T, E>;
