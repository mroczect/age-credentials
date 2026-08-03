//! Reading and writing encrypted private key files.
//!
//! This module provides functions to read encrypted Age private keys from files
//! and write them to disk. The encrypted key data is treated as sensitive and
//! is wrapped in [`Zeroizing`] when read, ensuring that it is securely zeroed
//! from memory when no longer needed.
//!
//! # Security
//! - The private key material is encrypted on disk; this module does **not**
//!   decrypt it. The data is read as opaque bytes.
//! - [`Zeroizing`] guarantees that the buffer is cleared on drop, mitigating
//!   the risk of accidental exposure via memory dumps.
//! - The write function rejects empty data to prevent accidental creation of
//!   zero‑length key files.

use crate::handler::error::{AgeCredentialsError, Result};
use std::path::Path;
use zeroize::Zeroizing;

/// Reads the entire contents of an encrypted private key file into a zeroizing
/// buffer.
///
/// # Arguments
/// * `path` – The path to the encrypted private key file (typically with a
///   `.age` extension).
///
/// # Behavior
/// 1. Reads the file as a raw byte vector.
/// 2. Wraps the vector in [`Zeroizing`] to ensure it is cleared on drop.
///
/// # Errors
/// Returns `AgeCredentialsError::Io` if reading the file fails.
///
/// # Example
/// ```
/// # use age_credentials::core::api::read_encrypted_private_key;
/// # let path = "private/secret.age";
/// let encrypted_data = read_encrypted_private_key(path)?;
/// // The data is automatically zeroized when `encrypted_data` goes out of scope.
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn read_encrypted_private_key(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>> {
    let path = path.as_ref().to_path_buf();
    let data = std::fs::read(&path).map_err(|e| AgeCredentialsError::Io { path, source: e })?;
    Ok(Zeroizing::new(data))
}

/// Writes encrypted private key data to a file.
///
/// # Arguments
/// * `path` – The target file path.
/// * `encrypted_key` – The encrypted key bytes to write.
///
/// # Behavior
/// 1. Validates that the data is not empty.
/// 2. Writes the data to the file, overwriting any existing content.
///
/// # Errors
/// - `AgeCredentialsError::InvalidData` – If the key data is empty.
/// - `AgeCredentialsError::Io` – If writing the file fails.
///
/// # Example
/// ```
/// # use age_credentials::core::api::write_encrypted_private_key;
/// # let path = "private/secret.age";
/// # let encrypted_data = b"encrypted-bytes";
/// write_encrypted_private_key(path, encrypted_data)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn write_encrypted_private_key(path: impl AsRef<Path>, encrypted_key: &[u8]) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    if encrypted_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypted private key write",
            details: "Encrypted key data is empty".into(),
        });
    }
    std::fs::write(&path, encrypted_key)
        .map_err(|e| AgeCredentialsError::Io { path, source: e })?;
    Ok(())
}
