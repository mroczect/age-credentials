use crate::handler::error::{AgeCredentialsError, Result};
use crate::handler::types::Metadata;
use std::path::Path;

const MAX_METADATA_SIZE: usize = 5 * 1024 * 1024;

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load(path: impl AsRef<Path>) -> Result<Metadata> {
        let path = path.as_ref().to_path_buf();

        let data = std::fs::read_to_string(&path).map_err(|e| AgeCredentialsError::Io {
            path: path.clone(),
            source: e,
        })?;
        if data.len() > MAX_METADATA_SIZE {
            return Err(AgeCredentialsError::InvalidData {
                context: "metadata file",
                details: format!(
                    "File too large: {} bytes (max {})",
                    data.len(),
                    MAX_METADATA_SIZE
                ),
            });
        }

        let metadata: Metadata =
            serde_json::from_str(&data).map_err(|e| AgeCredentialsError::Serialization {
                target: "metadata",
                path,
                source: e,
            })?;
        Ok(metadata)
    }

    pub fn save(path: impl AsRef<Path>, metadata: &Metadata) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        let json = serde_json::to_string_pretty(metadata).map_err(|e| {
            AgeCredentialsError::Serialization {
                target: "metadata",
                path: path.clone(),
                source: e,
            }
        })?;
        let parent = path.parent().ok_or_else(|| AgeCredentialsError::Config {
            message: "Metadata path has no parent directory".into(),
            location: file!().to_string(),
        })?;
        let mut tmp =
            tempfile::NamedTempFile::new_in(parent).map_err(|e| AgeCredentialsError::Io {
                path: path.clone(),
                source: e,
            })?;
        std::io::Write::write_all(&mut tmp, json.as_bytes()).map_err(|e| {
            AgeCredentialsError::Io {
                path: path.clone(),
                source: e,
            }
        })?;
        tmp.persist(&path).map_err(|e| AgeCredentialsError::Io {
            path: path.clone(),
            source: e.error,
        })?;
        Ok(())
    }
}
