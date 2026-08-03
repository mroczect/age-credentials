//! Key pair generation for Age encryption.
//!
//! This module provides functionality to generate a new X25519 key pair for Age.
//! The generated key pair consists of a public key (for encryption) and a
//! secret key (for decryption). The secret key is automatically zeroized when
//! dropped through the use of [`Zeroizing`] in the returned [`KeyGenData`]
//! struct.
//!
//! # Security
//! - The secret key is stored in a [`Zeroizing`] wrapper, ensuring it is
//!   securely cleared from memory when it goes out of scope.
//! - It is the caller's responsibility to persist the secret key securely
//!   (e.g., in an encrypted file) if it needs to be reused.
//! - The key pair is generated using the `librage` library, which delegates
//!   to a cryptographically secure random number generator.
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::generate_keypair;
//!
//! let keypair = generate_keypair()?;
//! println!("Public key: {}", keypair.public_key);
//! // The secret key is zeroized on drop
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use crate::handler::types::KeyGenData;

/// Generates a new Age X25519 key pair.
///
/// This function calls into the `librage` library to produce a new key pair
/// using a cryptographically secure random generator. The returned
/// [`KeyGenData`] contains the public key as a plain `String` and the secret
/// key as a [`Zeroizing<String>`], which is automatically zeroized on drop.
///
/// # Errors
/// Returns `AgeCredentialsError::KeyGenFailed` if:
/// - The underlying `librage` call fails (e.g., random number generator error).
/// - The `librage` response indicates success but contains no data.
/// - The `librage` response contains an error with a code and message.
///
/// # Panics
/// This function does not panic.
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::generate_keypair;
/// let keypair = generate_keypair()?;
/// assert!(keypair.public_key.starts_with("age"));
/// assert!(keypair.secret_key.starts_with("AGE-SECRET-KEY-"));
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn generate_keypair() -> Result<KeyGenData> {
    let response = librage::generate_keypair();
    if !response.success {
        let reason = match response.error {
            Some(e) => format!("{}: {}", e.code, e.message),
            None => "Unknown librage error".to_string(),
        };
        return Err(AgeCredentialsError::KeyGenFailed { reason });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::KeyGenFailed {
            reason: "librage returned success but no data".into(),
        })?;
    Ok(KeyGenData {
        public_key: data.public_key,
        secret_key: data.secret_key,
    })
}
