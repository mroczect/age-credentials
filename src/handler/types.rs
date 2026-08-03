//! Core data types used throughout the age-credentials crate.
//!
//! This module defines the fundamental types for representing identities,
//! metadata, fingerprints, and user identifiers. It also provides validation
//! functions for names and email addresses, and a container for freshly
//! generated key material.

use crate::AgeCredentialsError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// A cryptographic fingerprint represented as a hexadecimal string.
///
/// Fingerprints are used as unique identifiers for identities. They are derived
/// from Age public keys and are expected to be non‑empty and composed solely
/// of hexadecimal digits (0–9, a–f, A–F).
///
/// # Validation
/// The `new` constructor ensures the fingerprint meets the above criteria.
///
/// # Serde support
/// The type implements `Serialize` and `Deserialize` so it can be stored in
/// metadata files.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Creates a new `Fingerprint` from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex` - A string that should contain only hexadecimal digits.
    ///
    /// # Errors
    /// Returns `AgeCredentialsError::InvalidFingerprint` if the string is empty
    /// or contains non‑hexadecimal characters.
    ///
    /// # Example
    /// ```
    /// # use age_credentials::handler::types::Fingerprint;
    /// let fp = Fingerprint::new("deadbeef").unwrap();
    /// ```
    pub fn new(hex: impl Into<String>) -> Result<Self, AgeCredentialsError> {
        let hex = hex.into();
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AgeCredentialsError::InvalidFingerprint {
                reason: "must be non-empty hexadecimal".into(),
            });
        }
        Ok(Fingerprint(hex))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A user identity consisting of a name and an email address.
///
/// The `UserID` is used to associate a human‑readable identity with a
/// cryptographic key. Both fields are validated according to the rules defined
/// in `validate_user_name` and `validate_user_email`.
///
/// # Validation rules
/// - **Name**: Must be 2–255 characters long, trimmed, and contain only
///   alphabetic characters, digits, spaces, hyphens, apostrophes, and dots.
/// - **Email**: Must be non‑empty, at most 254 characters, contain exactly one
///   '@', have a non‑empty local part and domain, and contain only alphanumeric
///   characters, dots, hyphens, underscores, plus signs, and '@'.
///
/// # Serde support
/// The type implements `Serialize` and `Deserialize` for persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserID {
    /// The full name of the user.
    pub name: String,
    /// The email address of the user.
    pub email: String,
}

impl UserID {
    /// Creates a new `UserID` after validating the name and email.
    ///
    /// # Arguments
    /// * `name` - The full name.
    /// * `email` - The email address.
    ///
    /// # Errors
    /// Returns `AgeCredentialsError::InvalidUserId` if either field fails
    /// validation.
    ///
    /// # Example
    /// ```
    /// # use age_credentials::handler::types::UserID;
    /// let uid = UserID::new("Alice Example", "alice@example.com").unwrap();
    /// ```
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
    ) -> Result<Self, AgeCredentialsError> {
        let name = name.into();
        let email = email.into();
        validate_user_name_internal(&name)?;
        validate_user_email_internal(&email)?;
        Ok(Self {
            name: name.trim().to_string(),
            email: email.trim().to_string(),
        })
    }

    /// Formats the `UserID` as `"Name <email>"`.
    ///
    /// # Example
    /// ```
    /// # use age_credentials::handler::types::UserID;
    /// let uid = UserID::new("Alice Example", "alice@example.com").unwrap();
    /// assert_eq!(uid.to_formatted(), "Alice Example <alice@example.com>");
    /// ```
    pub fn to_formatted(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

/// Validates a user name according to the rules described for [`UserID`].
///
/// This is a convenience wrapper around the internal validation function.
///
/// # Errors
/// Returns `AgeCredentialsError::InvalidUserId` on failure.
pub fn validate_user_name(name: &str) -> Result<(), AgeCredentialsError> {
    validate_user_name_internal(name)
}

/// Validates an email address according to the rules described for [`UserID`].
///
/// This is a convenience wrapper around the internal validation function.
///
/// # Errors
/// Returns `AgeCredentialsError::InvalidUserId` on failure.
pub fn validate_user_email(email: &str) -> Result<(), AgeCredentialsError> {
    validate_user_email_internal(email)
}

fn validate_user_name_internal(name: &str) -> Result<(), AgeCredentialsError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Name cannot be empty".into(),
        });
    }
    if trimmed.len() < 2 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: format!("Name too short: {} chars, minimum 2", trimmed.len()),
        });
    }
    if trimmed.len() > 255 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: format!("Name too long: {} chars, maximum 255", trimmed.len()),
        });
    }
    for (i, c) in trimmed.char_indices() {
        let valid =
            c.is_alphabetic() || c.is_numeric() || c == ' ' || c == '-' || c == '\'' || c == '.';
        if !valid {
            return Err(AgeCredentialsError::InvalidUserId {
                reason: format!("Invalid character '{}' at position {} in name", c, i + 1),
            });
        }
    }
    Ok(())
}

fn validate_user_email_internal(email: &str) -> Result<(), AgeCredentialsError> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Email cannot be empty".into(),
        });
    }
    if trimmed.len() > 254 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: format!("Email too long: {} chars, maximum 254", trimmed.len()),
        });
    }
    let at_count = trimmed.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Email must contain exactly one '@'".into(),
        });
    }
    let parts: Vec<&str> = trimmed.split('@').collect();
    if parts[0].is_empty() || parts[1].is_empty() {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Email local part or domain is empty".into(),
        });
    }
    for (i, c) in trimmed.char_indices() {
        let valid = c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '@' || c == '+';
        if !valid {
            return Err(AgeCredentialsError::InvalidUserId {
                reason: format!("Invalid character '{}' at position {} in email", c, i + 1),
            });
        }
    }
    Ok(())
}

/// A complete identity entry in the keyring.
///
/// An `Identity` associates a fingerprint with a user, stores the paths to
/// the corresponding encrypted private key and public key files, and includes
/// an optional label and creation timestamp.
///
/// # Fields
/// * `fingerprint` – Unique fingerprint of the identity.
/// * `user_id` – The user's name and email.
/// * `label` – An optional, user‑defined label (e.g., "work key").
/// * `private_key_path` – Filesystem path to the encrypted private key (`.age` file).
/// * `public_key_path` – Filesystem path to the public key (`.pub` file).
/// * `created_at` – Unix timestamp (seconds since epoch) of creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub fingerprint: Fingerprint,
    pub user_id: UserID,
    pub label: Option<String>,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub created_at: i64,
}

/// The full metadata of a keyring.
///
/// `Metadata` is the top‑level structure stored in `metadata.json`. It contains
/// all identities and optionally indicates which identity is the default.
///
/// # Serde support
/// The type implements `Serialize` and `Deserialize`, and provides a `Default`
/// implementation (empty vector, no default identity).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    /// The list of all identities in the keyring.
    pub identities: Vec<Identity>,
    /// The fingerprint of the default identity, if any.
    pub default_identity: Option<Fingerprint>,
}

/// Freshly generated key material.
///
/// Returned by key generation functions. The secret key is wrapped in
/// [`Zeroizing`] to ensure it is securely zeroed when dropped.
///
/// # Fields
/// * `public_key` – The Age public key as a string.
/// * `secret_key` – The Age secret key as a string, zeroized on drop.
#[derive(Debug, Clone)]
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
