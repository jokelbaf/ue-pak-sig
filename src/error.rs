use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid sig file magic: expected 0x73832DAA, got 0x{0:08X}")]
    InvalidMagic(u32),

    #[error("unsupported sig file version: {0}")]
    UnsupportedVersion(i32),

    #[error("invalid ini: {0}")]
    InvalidIni(String),

    #[error("RSA error: {0}")]
    Rsa(String),

    #[error("invalid pak file: {0}")]
    InvalidPak(String),

    #[error("signature validation failed")]
    SignatureMismatch,

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}
