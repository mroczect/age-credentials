//! Reading and writing public key files.
//!
//! This module provides functions to read Age public keys from files, validate
//! their format, and write them to disk. Validation ensures that the key is a
//! valid `age::x25519::Recipient` before it is stored or returned.
//!
//! # File format
//! Public key files are expected to contain a single Age public key string,
//! optionally with leading/trailing whitespace. When writing, a newline is
//! automatically appended.

use crate::handler::error::{AgeCredentialsError, Result};
use std::path::Path;

/// Reads a public key from a file and validates it.
///
/// # Arguments
/// * `path` – The path to the public key file.
///
/// # Behavior
/// 1. Reads the file content as a UTF‑8 string.
/// 2. Trims leading and trailing whitespace.
/// 3. Validates that the trimmed string is a valid Age X25519 recipient key.
///
/// # Errors
/// - `AgeCredentialsError::Io` – If reading the file fails.
/// - `AgeCredentialsError::InvalidData` – If the key is empty or fails
///   validation.
///
/// # Example
/// ```
/// # use age_credentials::core::api::read_public_key;
/// # let path = "public_key.pub";
/// let key = read_public_key(path)?;
/// assert!(key.starts_with("age"));
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn read_public_key(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref().to_path_buf();
    let content = std::fs::read_to_string(&path).map_err(|e| AgeCredentialsError::Io {
        path: path.clone(),
        source: e,
    })?;
    let key = content.trim().to_string();
    validate_public_key_string(&key)?;
    Ok(key)
}

/// Writes a public key to a file after validation.
///
/// # Arguments
/// * `path` – The target file path.
/// * `public_key` – The public key string to write.
///
/// # Behavior
/// 1. Validates the key using [`validate_public_key_string`].
/// 2. Writes the key to the file with a trailing newline.
///
/// # Errors
/// - `AgeCredentialsError::InvalidData` – If the key is invalid.
/// - `AgeCredentialsError::Io` – If writing the file fails.
///
/// # Example
/// ```
/// # use age_credentials::core::api::write_public_key;
/// # let path = "public_key.pub";
/// let key = "age1...";
/// write_public_key(path, key)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn write_public_key(path: impl AsRef<Path>, public_key: &str) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    validate_public_key_string(public_key)?;
    std::fs::write(&path, format!("{}\n", public_key))
        .map_err(|e| AgeCredentialsError::Io { path, source: e })?;
    Ok(())
}

/// Validates that a string is a non‑empty Age X25519 public key.
///
/// This function is used internally to ensure that public keys are syntactically
/// correct before they are read or written.
///
/// # Arguments
/// * `key` – The public key string (should not include trailing newline).
///
/// # Errors
/// Returns `AgeCredentialsError::InvalidData` if:
/// - The key is empty, or
/// - Parsing as `age::x25519::Recipient` fails.
fn validate_public_key_string(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "public key",
            details: "Public key is empty".into(),
        });
    }
    key.parse::<age::x25519::Recipient>()
        .map_err(|_| AgeCredentialsError::InvalidData {
            context: "public key",
            details: format!("Invalid age public key: {}", key),
        })?;
    Ok(())
}
