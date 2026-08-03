use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgeCredentialsError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Serialization error for {target} at {path}: {source}")]
    Serialization {
        target: &'static str,
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Duplicate identity {fingerprint} in keyring at {keyring_path}")]
    DuplicateIdentity {
        fingerprint: String,
        keyring_path: PathBuf,
    },

    #[error("Identity not found: {search_key} in keyring at {keyring_path}")]
    IdentityNotFound {
        search_key: String,
        keyring_path: PathBuf,
    },

    #[error("Invalid email address: {email}")]
    InvalidEmail { email: String },

    #[error("Invalid name: {name}")]
    InvalidName { name: String },

    #[error("Passphrase incorrect for identity {identity}")]
    PassphraseIncorrect { identity: String },

    #[error("Encryption failed for recipients {recipients:?}: [{code}] {message}")]
    EncryptionFailed {
        recipients: Vec<String>,
        code: String,
        message: String,
    },

    #[error("Decryption failed for identity {identity:?} (hint: {hint}): [{code}] {message}")]
    DecryptionFailed {
        identity: Option<String>,
        hint: String,
        code: String,
        message: String,
    },

    #[error("Key generation failed: {reason}")]
    KeyGenFailed { reason: String },

    #[error("Metadata file not found at {path}")]
    MetadataNotFound { path: PathBuf },

    #[error("Invalid data in {context}: {details}")]
    InvalidData {
        context: &'static str,
        details: String,
    },

    #[error("Configuration error: {message} (at {location})")]
    Config { message: String, location: String },

    #[error("Passphrase too short: {length} chars, minimum {min_length}")]
    PassphraseTooShort { length: usize, min_length: usize },

    #[error("Invalid fingerprint: {reason}")]
    InvalidFingerprint { reason: String },

    #[error("Invalid User ID: {reason}")]
    InvalidUserId { reason: String },
}

pub type Result<T> = std::result::Result<T, AgeCredentialsError>;
