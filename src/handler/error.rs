use librage::LibrageError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgeCredentialsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Librage(#[from] LibrageError),

    #[error("Identity already exists: {0}")]
    DuplicateIdentity(String),

    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Invalid email address: {0}")]
    InvalidEmail(String),

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Incorrect passphrase")]
    PassphraseIncorrect,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenFailed(String),

    #[error("Metadata file not found: {0}")]
    MetadataNotFound(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, AgeCredentialsError>;
