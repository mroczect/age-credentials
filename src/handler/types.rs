use crate::AgeCredentialsError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(String);

impl Fingerprint {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserID {
    pub name: String,
    pub email: String,
}

impl UserID {
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

    pub fn to_formatted(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

pub fn validate_user_name(name: &str) -> Result<(), AgeCredentialsError> {
    validate_user_name_internal(name)
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub fingerprint: Fingerprint,
    pub user_id: UserID,
    pub label: Option<String>,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub identities: Vec<Identity>,
    pub default_identity: Option<Fingerprint>,
}

#[derive(Debug, Clone)]
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
