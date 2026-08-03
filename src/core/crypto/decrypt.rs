//! Decryption of Age ciphertext using a secret key.
//!
//! This module provides the `decrypt` function, which takes binary ciphertext
//! produced by any Age encryption (single or multiple recipients) and decrypts
//! it using a matching secret key.
//!
//! # Usage
//! The decryption function is straightforward: provide the ciphertext bytes
//! and the secret key string. It returns the plaintext bytes on success.
//!
//! # Errors
//! Decryption can fail for several reasons:
//! - The secret key is empty or invalid.
//! - The secret key does not correspond to any recipient used for encryption.
//! - The ciphertext is corrupted or malformed.
//! - The underlying `librage` library returns an error.
//!
//! In all cases, an `AgeCredentialsError::DecryptionFailed` is returned with
//! a descriptive code and message, and a hint for debugging.
//!
//! # Security
//! - The secret key is passed as a plain `&str`. Callers should ensure that
//!   the secret key is handled securely and not logged or persisted.
//! - The plaintext is returned as a `Vec<u8>`. Callers should consider using
//!   zeroizing wrappers if the plaintext is sensitive.
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::decrypt;
//!
//! let ciphertext = vec![...]; // from encryption
//! let secret_key = "AGE-SECRET-KEY-...";
//! let plaintext = decrypt(&ciphertext, secret_key)?;
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};

/// Decrypts binary ciphertext using an Age secret key.
///
/// # Arguments
/// * `ciphertext` – The encrypted data as a byte slice (binary format, not armored).
/// * `secret_key` – A valid Age X25519 secret key string (starts with
///   `"AGE-SECRET-KEY-"`).
///
/// # Errors
/// Returns an error if:
/// - The secret key is empty (`InvalidData`).
/// - The decryption operation fails (`DecryptionFailed`). The error includes
///   a code, a message from the underlying library, and a hint to verify the
///   secret key or ciphertext integrity.
///
/// # Panics
/// This function does not panic.
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::decrypt;
/// # let ciphertext = b"encrypted";
/// # let secret_key = "AGE-SECRET-KEY-...";
/// let plaintext = decrypt(ciphertext, secret_key)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>> {
    if secret_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "decrypt",
            details: "secret key is empty".into(),
        });
    }
    let response = librage::decrypt(ciphertext, secret_key);
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AgeCredentialsError::DecryptionFailed {
                identity: None,
                hint: "librage returned failure without error details".into(),
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AgeCredentialsError::DecryptionFailed {
            identity: None,
            hint: "Verify secret key or ciphertext integrity".into(),
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::DecryptionFailed {
            identity: None,
            hint: "librage returned success but no data".into(),
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.plaintext.to_vec())
}
