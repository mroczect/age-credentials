use crate::domain::error::{AccountError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn new(hex: impl Into<String>) -> Result<Self> {
        let hex = hex.into();
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AccountError::InvalidFingerprint {
                reason: "must be non-empty hexadecimal".into(),
            });
        }
        Ok(Fingerprint(hex))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Fingerprint> for String {
    fn from(fp: Fingerprint) -> Self {
        fp.0
    }
}
