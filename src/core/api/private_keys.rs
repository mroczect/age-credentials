use crate::handler::error::{AgeCredentialsError, Result};
use std::path::Path;

pub fn read_encrypted_private_key(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref().to_path_buf();
    std::fs::read(&path).map_err(|e| AgeCredentialsError::Io { path, source: e })
}

pub fn write_encrypted_private_key(path: impl AsRef<Path>, encrypted_key: &[u8]) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    if encrypted_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypted private key write",
            details: "Encrypted key data is empty".into(),
        });
    }
    std::fs::write(&path, encrypted_key)
        .map_err(|e| AgeCredentialsError::Io { path, source: e })?;
    Ok(())
}
