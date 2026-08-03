//! Error types for the age-credentials crate.
//!
//! This module defines the primary error type [`AgeCredentialsError`] and a
//! convenience [`Result`] alias. All fallible operations in this crate return
//! `Result<T>` with this error type.

use std::path::PathBuf;
use thiserror::Error;

/// Comprehensive error type for all failures that can occur in the
/// age-credentials crate.
///
/// Each variant corresponds to a specific failure mode, carrying contextual
/// information to aid diagnosis and recovery. The error is designed to be
/// actionable and to provide clear messages.
#[derive(Error, Debug)]
pub enum AgeCredentialsError {
    /// An I/O error occurred while accessing a file or directory.
    ///
    /// This variant wraps a standard `std::io::Error` and includes the path
    /// that caused the failure.
    ///
    /// # Fields
    /// * `path` - The file system path involved in the operation.
    /// * `source` - The underlying `std::io::Error`.
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A serialization or deserialization error occurred (JSON, TOML, etc.).
    ///
    /// Used when data cannot be parsed into or from a structured format.
    ///
    /// # Fields
    /// * `target` - The intended serialization format or context (e.g., "metadata", "json").
    /// * `path` - The file path involved, if any (use `<memory>` for in-memory operations).
    /// * `source` - The underlying serialization error, boxed as a trait object.
    #[error("Serialization error for {target} at {path}: {source}")]
    Serialization {
        target: &'static str,
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// An attempt was made to add an identity with a fingerprint that already
    /// exists in the keyring.
    ///
    /// # Fields
    /// * `fingerprint` - The duplicate fingerprint (as a hex string).
    /// * `keyring_path` - The root path of the keyring where the duplicate was found.
    #[error("Duplicate identity {fingerprint} in keyring at {keyring_path}")]
    DuplicateIdentity {
        fingerprint: String,
        keyring_path: PathBuf,
    },

    /// An identity could not be found in the keyring using a given search key.
    ///
    /// # Fields
    /// * `search_key` - The key used for lookup (e.g., fingerprint, email, or user ID).
    /// * `keyring_path` - The root path of the keyring searched.
    #[error("Identity not found: {search_key} in keyring at {keyring_path}")]
    IdentityNotFound {
        search_key: String,
        keyring_path: PathBuf,
    },

    /// The provided email address is invalid.
    ///
    /// # Fields
    /// * `email` - The invalid email string.
    #[error("Invalid email address: {email}")]
    InvalidEmail { email: String },

    /// The provided name is invalid.
    ///
    /// # Fields
    /// * `name` - The invalid name string.
    #[error("Invalid name: {name}")]
    InvalidName { name: String },

    /// The passphrase provided for an identity is incorrect.
    ///
    /// # Fields
    /// * `identity` - The fingerprint or identifier of the identity.
    #[error("Passphrase incorrect for identity {identity}")]
    PassphraseIncorrect { identity: String },

    /// Encryption of data failed.
    ///
    /// This typically occurs when the provided recipient(s) are invalid, or the
    /// underlying cryptographic library (`librage`) returns an error.
    ///
    /// # Fields
    /// * `recipients` - The list of recipients (public keys) that were used.
    /// * `code` - An error code returned by the cryptographic backend.
    /// * `message` - A descriptive error message from the backend.
    #[error("Encryption failed for recipients {recipients:?}: [{code}] {message}")]
    EncryptionFailed {
        recipients: Vec<String>,
        code: String,
        message: String,
    },

    /// Decryption of ciphertext failed.
    ///
    /// This can happen if the secret key does not match any recipient, the
    /// ciphertext is corrupted, or the passphrase is wrong.
    ///
    /// # Fields
    /// * `identity` - Optional fingerprint or identifier used for decryption.
    /// * `hint` - A suggested action to resolve the issue (e.g., "Check passphrase").
    /// * `code` - An error code from the cryptographic backend.
    /// * `message` - A descriptive error message from the backend.
    #[error("Decryption failed for identity {identity:?} (hint: {hint}): [{code}] {message}")]
    DecryptionFailed {
        identity: Option<String>,
        hint: String,
        code: String,
        message: String,
    },

    /// Key generation failed.
    ///
    /// # Fields
    /// * `reason` - A human-readable explanation of why generation failed.
    #[error("Key generation failed: {reason}")]
    KeyGenFailed { reason: String },

    /// The metadata file could not be found at the expected location.
    ///
    /// # Fields
    /// * `path` - The path where the metadata file was expected.
    #[error("Metadata file not found at {path}")]
    MetadataNotFound { path: PathBuf },

    /// The data provided is invalid or malformed in a specific context.
    ///
    /// # Fields
    /// * `context` - A static string describing the context (e.g., "recipient file").
    /// * `details` - A detailed description of the validation failure.
    #[error("Invalid data in {context}: {details}")]
    InvalidData {
        context: &'static str,
        details: String,
    },

    /// A configuration error occurred, typically due to an invalid setting.
    ///
    /// # Fields
    /// * `message` - The error message.
    /// * `location` - The source file and line number where the error was raised (via `file!()`).
    #[error("Configuration error: {message} (at {location})")]
    Config { message: String, location: String },

    /// The provided passphrase is too short.
    ///
    /// # Fields
    /// * `length` - The actual length of the passphrase.
    /// * `min_length` - The minimum required length.
    #[error("Passphrase too short: {length} chars, minimum {min_length}")]
    PassphraseTooShort { length: usize, min_length: usize },

    /// The fingerprint string is invalid (e.g., empty or non‑hexadecimal).
    ///
    /// # Fields
    /// * `reason` - A description of the validation failure.
    #[error("Invalid fingerprint: {reason}")]
    InvalidFingerprint { reason: String },

    /// A User ID (name or email) failed validation.
    ///
    /// # Fields
    /// * `reason` - A description of why the User ID is invalid.
    #[error("Invalid User ID: {reason}")]
    InvalidUserId { reason: String },
}

/// A specialized `Result` type for operations that can fail with an
/// [`AgeCredentialsError`].
///
/// This is the standard result type used throughout the crate.
pub type Result<T> = std::result::Result<T, AgeCredentialsError>;
