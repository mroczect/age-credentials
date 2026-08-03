use crate::handler::error::{AgeCredentialsError, Result};
use std::path::Path;

pub fn read_public_key(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref().to_path_buf();
    let content = std::fs::read_to_string(&path).map_err(|e| AgeCredentialsError::Io {
        path: path.clone(),
        source: e,
    })?;
    let key = content.trim().to_string();
    validate_public_key_string(&key)?;
    Ok(key)
}

pub fn write_public_key(path: impl AsRef<Path>, public_key: &str) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    validate_public_key_string(public_key)?;
    std::fs::write(&path, format!("{}\n", public_key))
        .map_err(|e| AgeCredentialsError::Io { path, source: e })?;
    Ok(())
}

fn validate_public_key_string(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "public key",
            details: "Public key is empty".into(),
        });
    }
    key.parse::<age::x25519::Recipient>()
        .map_err(|_| AgeCredentialsError::InvalidData {
            context: "public key",
            details: format!("Invalid age public key: {}", key),
        })?;
    Ok(())
}
