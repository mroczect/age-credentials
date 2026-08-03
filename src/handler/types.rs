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
        if name.trim().is_empty() {
            return Err(AgeCredentialsError::InvalidUserId {
                reason: "Name cannot be empty".into(),
            });
        }
        if !email.contains('@') {
            return Err(AgeCredentialsError::InvalidUserId {
                reason: "Email must contain '@'".into(),
            });
        }
        Ok(Self { name, email })
    }

    pub fn to_formatted(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
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
