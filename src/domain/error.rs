use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccountError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[error("Serialization error: {source}")]
    Serialization {
        #[from]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Backend error: {0}")]
    Backend(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Duplicate account: {0}")]
    DuplicateAccount(String),

    #[error("Invalid data in {context}: {details}")]
    InvalidData {
        context: &'static str,
        details: String,
    },

    #[error("Encryption failed for recipients {recipients:?}: [{code}] {message}")]
    EncryptionFailed {
        recipients: Vec<String>,
        code: String,
        message: String,
    },

    #[error("Decryption failed (hint: {hint}): [{code}] {message}")]
    DecryptionFailed {
        hint: String,
        code: String,
        message: String,
    },

    #[error("Key generation failed: {reason}")]
    KeyGenFailed { reason: String },

    #[error("Passphrase too short: {length} chars, minimum {min_length}")]
    PassphraseTooShort { length: usize, min_length: usize },

    #[error("Invalid fingerprint: {reason}")]
    InvalidFingerprint { reason: String },

    #[error("Invalid User ID: {reason}")]
    InvalidUserId { reason: String },
}

pub type Result<T> = std::result::Result<T, AccountError>;
