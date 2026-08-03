//! ASCII‑armored encryption using Age.
//!
//! This module provides functions to encrypt data using Age public keys with
//! ASCII‑armored output. Armored encryption wraps the binary ciphertext in a
//! Base64‑encoded, human‑readable format that is safe to transmit via email,
//! copy‑paste, or store in text files.
//!
//! # When to use armored encryption
//! - When you need to share encrypted data as text (e.g., in an email or a
//!   configuration file).
//! - When you want to visually inspect or manually copy the encrypted output.
//!
//! # When to use binary encryption
//! - When storage size is critical (armored output is ~33% larger).
//! - When you are writing to a file and plan to read it programmatically.
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::armor::encrypt_armored;
//!
//! let plaintext = b"Hello, secret world!";
//! let public_key = "age1..."; // A valid Age public key
//! let armored = encrypt_armored(plaintext, public_key)?;
//! // The output is a Vec<u8> containing ASCII armor text.
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};

/// Extracts the ciphertext from a `librage` encryption response.
///
/// This helper function handles the common pattern of checking the response
/// for success, extracting error details if present, and retrieving the
/// ciphertext. It is used internally by both single‑recipient and
/// multi‑recipient encryption functions.
///
/// # Arguments
/// * `response` – The response from `librage`.
/// * `recipients` – The list of recipients used (for error context).
///
/// # Returns
/// The ciphertext bytes on success.
///
/// # Errors
/// Returns `AgeCredentialsError::EncryptionFailed` if the response indicates
/// failure or lacks data.
fn extract_armor_error(
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

/// Encrypts plaintext with a single public key and returns ASCII‑armored
/// ciphertext.
///
/// # Arguments
/// * `plaintext` – The data to encrypt.
/// * `public_key` – A valid Age X25519 public key string.
///
/// # Behavior
/// 1. Validates that the public key is not empty.
/// 2. Calls `librage::encrypt_armored`, which produces an ASCII‑armored output.
/// 3. Extracts the ciphertext or returns an error.
///
/// # Errors
/// - `AgeCredentialsError::InvalidData` – If the public key is empty.
/// - `AgeCredentialsError::EncryptionFailed` – If the underlying encryption
///   fails (e.g., invalid key, network error, or librage internal error).
///
/// # Example
/// ```
/// use age_credentials::core::crypto::armor::encrypt_armored;
///
/// let plaintext = b"secret";
/// let pubkey = "age1..."; // replace with a real key
/// let armored = encrypt_armored(plaintext, pubkey)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn encrypt_armored(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    if public_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "armor encrypt",
            details: "public key is empty".into(),
        });
    }
    let response = librage::encrypt_armored(plaintext, public_key);
    extract_armor_error(response, vec![public_key.to_owned()])
}

/// Encrypts plaintext with multiple public keys and returns ASCII‑armored
/// ciphertext.
///
/// The resulting ciphertext can be decrypted by any of the recipients.
///
/// # Arguments
/// * `plaintext` – The data to encrypt.
/// * `public_keys` – A slice of valid Age X25519 public key strings.
///
/// # Behavior
/// 1. Validates that at least one key is provided.
/// 2. Calls `librage::encrypt_multiple_armored` with all keys.
/// 3. Extracts the ciphertext or returns an error.
///
/// # Errors
/// - `AgeCredentialsError::InvalidData` – If the key slice is empty.
/// - `AgeCredentialsError::EncryptionFailed` – If encryption fails.
///
/// # Example
/// ```
/// use age_credentials::core::crypto::armor::encrypt_multiple_armored;
///
/// let plaintext = b"shared secret";
/// let keys = &["age1...", "age2..."]; // at least one
/// let armored = encrypt_multiple_armored(plaintext, keys)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn encrypt_multiple_armored(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>> {
    if public_keys.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "armor encrypt multiple",
            details: "at least one public key required".into(),
        });
    }
    let response = librage::encrypt_multiple_armored(plaintext, public_keys);
    let recipients: Vec<String> = public_keys.iter().map(|s| s.to_string()).collect();
    extract_armor_error(response, recipients)
}
