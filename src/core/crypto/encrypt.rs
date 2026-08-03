//! Encryption of data using Age public keys (binary format).
//!
//! This module provides functions to encrypt plaintext using one or more Age
//! X25519 public keys. The output is binary ciphertext (not ASCII-armored),
//! which is compact and suitable for storage in files or binary protocols.
//!
//! # Binary vs. Armored
//! - **Binary encryption** (this module) produces a compact binary format.
//!   Use this when file size or transmission efficiency is important.
//! - **Armored encryption** (the `armor` module) produces ASCII-armored output,
//!   which is human-readable and safe for text-based contexts (e.g., email,
//!   configuration files).
//!
//! # Multi-Recipient Encryption
//! The `encrypt_multiple` function allows you to encrypt data so that any of
//! the specified recipients can decrypt it. This is useful for sharing a secret
//! with a group.
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::encrypt;
//! use age_credentials::core::crypto::decrypt;
//!
//! let plaintext = b"Top secret message";
//! let pubkey = "age1..."; // valid Age public key
//! let seckey = "AGE-SECRET-KEY-..."; // corresponding secret key
//!
//! let ciphertext = encrypt(plaintext, pubkey)?;
//! let decrypted = decrypt(&ciphertext, seckey)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};

/// Helper function to extract ciphertext from a `librage` encryption response.
///
/// This internal function handles the common pattern of checking the response
/// for success, retrieving error details if present, and extracting the
/// ciphertext. It is used by both `encrypt` and `encrypt_multiple`.
///
/// # Arguments
/// * `response` – The response from `librage::encrypt` or `librage::encrypt_multiple`.
/// * `recipients` – The list of recipients used (for error context).
///
/// # Returns
/// The ciphertext bytes on success.
///
/// # Errors
/// Returns `AgeCredentialsError::EncryptionFailed` if the response indicates
/// failure or lacks data.
fn extract_encrypt_error(
    response: librage::LibrageResponse<librage::EncryptOutput>,
    recipients: Vec<String>,
) -> Result<Vec<u8>> {
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
                recipients: recipients.clone(),
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients,
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
            recipients,
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}

/// Encrypts plaintext with a single public key (binary output).
///
/// This function produces compact binary ciphertext that can be decrypted
/// by the holder of the corresponding secret key.
///
/// # Arguments
/// * `plaintext` – The data to encrypt.
/// * `public_key` – A valid Age X25519 public key string (starts with `"age"`).
///
/// # Errors
/// - `AgeCredentialsError::InvalidData` – If the public key is empty.
/// - `AgeCredentialsError::EncryptionFailed` – If encryption fails (e.g.,
///   invalid key format or `librage` error).
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::encrypt;
/// # let plaintext = b"secret";
/// # let pubkey = "age1...";
/// let ciphertext = encrypt(plaintext, pubkey)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    if public_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypt",
            details: "public key is empty".into(),
        });
    }
    let response = librage::encrypt(plaintext, public_key);
    extract_encrypt_error(response, vec![public_key.to_owned()])
}

/// Encrypts plaintext with multiple public keys (binary output).
///
/// The resulting ciphertext can be decrypted by any of the specified
/// recipients. This is useful for sharing data with multiple parties
/// without having to encrypt separately for each.
///
/// # Arguments
/// * `plaintext` – The data to encrypt.
/// * `public_keys` – A slice of valid Age X25519 public key strings.
///
/// # Errors
/// - `AgeCredentialsError::InvalidData` – If the key slice is empty.
/// - `AgeCredentialsError::EncryptionFailed` – If encryption fails.
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::encrypt_multiple;
/// # let plaintext = b"shared secret";
/// # let keys = &["age1...", "age2..."];
/// let ciphertext = encrypt_multiple(plaintext, keys)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn encrypt_multiple(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>> {
    if public_keys.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypt multiple",
            details: "at least one public key required".into(),
        });
    }
    let response = librage::encrypt_multiple(plaintext, public_keys);
    let recipients: Vec<String> = public_keys.iter().map(|s| s.to_string()).collect();
    extract_encrypt_error(response, recipients)
}
