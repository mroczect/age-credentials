use crate::handler::error::{AgeCredentialsError, Result};
use std::path::Path;

pub fn read_public_key(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref().to_path_buf();
    let content = std::fs::read_to_string(&path).map_err(|e| AgeCredentialsError::Io {
        path: path.clone(),
        source: e,
    })?;
    let key = content.trim().to_string();
    if key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "public key file",
            details: format!("File is empty: {}", path.display()),
        });
    }
    if !key.starts_with("age1") {
        return Err(AgeCredentialsError::InvalidData {
            context: "public key file",
            details: format!(
                "Invalid public key format (must start with 'age1'): {}",
                path.display()
            ),
        });
    }
    Ok(key)
}

pub fn write_public_key(path: impl AsRef<Path>, public_key: &str) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    if public_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "public key write",
            details: "Public key is empty".into(),
        });
    }
    if !public_key.starts_with("age1") {
        return Err(AgeCredentialsError::InvalidData {
            context: "public key write",
            details: "Public key must start with 'age1'".into(),
        });
    }
    std::fs::write(&path, format!("{}\n", public_key))
        .map_err(|e| AgeCredentialsError::Io { path, source: e })?;
    Ok(())
}
