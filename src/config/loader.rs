use crate::handler::error::{AgeCredentialsError, Result};
use crate::handler::types::Metadata;
use std::path::Path;

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load(path: impl AsRef<Path>) -> Result<Metadata> {
        let path = path.as_ref().to_path_buf();
        let data = std::fs::read_to_string(&path).map_err(|e| AgeCredentialsError::Io {
            path: path.clone(),
            source: e,
        })?;
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
        let tmp_path = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(metadata).map_err(|e| {
            AgeCredentialsError::Serialization {
                target: "metadata",
                path: path.clone(),
                source: e,
            }
        })?;
        std::fs::write(&tmp_path, &json).map_err(|e| AgeCredentialsError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp_path, &path).map_err(|e| AgeCredentialsError::Io {
            path: path.clone(),
            source: e,
        })?;
        Ok(())
    }
}
