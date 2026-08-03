//! Passphrase-based encryption and decryption for Age.
//!
//! This module provides functions to encrypt and decrypt data using a
//! user-provided passphrase instead of public/private key pairs. This is
//! useful for scenarios where key management is not desired, and the data
//! is only meant to be accessed by someone who knows the passphrase.
//!
//! # Security Considerations
//! - The passphrase must be at least 8 characters long (enforced by the
//!   `MIN_PASSPHRASE_LEN` constant).
//! - The security of the encrypted data depends entirely on the strength of
//!   the passphrase. Weak or short passphrases can be brute-forced.
//! - The passphrase is passed as a plain `&str`. It is the caller's
//!   responsibility to handle it securely (e.g., read from a secure input,
//!   zeroize after use).
//! - The underlying `librage` library uses the scrypt key derivation function
//!   to derive an encryption key from the passphrase, making brute-force
//!   attacks more expensive.
//!
//! # Output Format
//! Both encryption functions produce binary ciphertext (not ASCII-armored).
//! The ciphertext includes the scrypt parameters and salt, so the same
//! passphrase can be used to decrypt it without additional parameters.
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::passphrase::{
//!     encrypt_with_passphrase,
//!     decrypt_with_passphrase,
//! };
//!
//! let plaintext = b"Secret message";
//! let passphrase = "my-strong-passphrase";
//!
//! let ciphertext = encrypt_with_passphrase(plaintext, passphrase)?;
//! let decrypted = decrypt_with_passphrase(&ciphertext, passphrase)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};

/// The minimum required length for a passphrase (8 characters).
const MIN_PASSPHRASE_LEN: usize = 8;

/// Encrypts plaintext using a passphrase.
///
/// This function derives an encryption key from the passphrase using scrypt,
/// then encrypts the plaintext using the Age format.
///
/// # Arguments
/// * `plaintext` – The data to encrypt.
/// * `passphrase` – The passphrase to use for encryption.
///
/// # Requirements
/// - The passphrase must be at least 8 characters long.
///
/// # Errors
/// - `AgeCredentialsError::PassphraseTooShort` – If the passphrase is shorter
///   than 8 characters.
/// - `AgeCredentialsError::EncryptionFailed` – If the underlying `librage`
///   encryption fails.
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::passphrase::encrypt_with_passphrase;
/// let plaintext = b"secret";
/// let passphrase = "secure-passphrase";
/// let ciphertext = encrypt_with_passphrase(plaintext, passphrase)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(AgeCredentialsError::PassphraseTooShort {
            length: passphrase.len(),
            min_length: MIN_PASSPHRASE_LEN,
        });
    }
    let response = librage::encrypt_with_passphrase(plaintext, passphrase);
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
                recipients: vec!["<passphrase>".to_owned()],
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: vec!["<passphrase>".to_owned()],
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
            recipients: vec!["<passphrase>".to_owned()],
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}

/// Decrypts ciphertext that was encrypted with a passphrase.
///
/// This function derives the encryption key from the passphrase (using the
/// parameters embedded in the ciphertext), then decrypts the data.
///
/// # Arguments
/// * `ciphertext` – The encrypted data (binary format, produced by
///   `encrypt_with_passphrase`).
/// * `passphrase` – The passphrase to use for decryption.
///
/// # Requirements
/// - The passphrase must be at least 8 characters long.
///
/// # Errors
/// - `AgeCredentialsError::PassphraseTooShort` – If the passphrase is shorter
///   than 8 characters.
/// - `AgeCredentialsError::DecryptionFailed` – If decryption fails. This can
///   happen if the passphrase is incorrect or the ciphertext is corrupted.
///   The error includes a hint to check the passphrase.
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::passphrase::decrypt_with_passphrase;
/// # let ciphertext = vec![];
/// # let passphrase = "secure-passphrase";
/// let plaintext = decrypt_with_passphrase(&ciphertext, passphrase)?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(AgeCredentialsError::PassphraseTooShort {
            length: passphrase.len(),
            min_length: MIN_PASSPHRASE_LEN,
        });
    }
    let response = librage::decrypt_with_passphrase(ciphertext, passphrase);
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
            hint: "Check passphrase".into(),
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
