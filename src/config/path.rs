use crate::handler::error::{AgeCredentialsError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct KeyringPath {
    root: PathBuf,
}

impl KeyringPath {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(AgeCredentialsError::Config {
                message: "Keyring path cannot be empty".into(),
                location: file!().to_string(),
            });
        }
        let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        std::fs::create_dir_all(&absolute).map_err(|e| AgeCredentialsError::Io {
            path: absolute.clone(),
            source: e,
        })?;
        std::fs::create_dir_all(absolute.join("private")).map_err(|e| AgeCredentialsError::Io {
            path: absolute.join("private"),
            source: e,
        })?;
        std::fs::create_dir_all(absolute.join("public")).map_err(|e| AgeCredentialsError::Io {
            path: absolute.join("public"),
            source: e,
        })?;
        Ok(Self { root: absolute })
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(AgeCredentialsError::Config {
                message: format!("Keyring directory not found: {}", path.display()),
                location: file!().to_string(),
            });
        }
        let absolute = std::fs::canonicalize(path).map_err(|e| AgeCredentialsError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self { root: absolute })
    }

    pub fn metadata_file(&self) -> PathBuf {
        self.root.join("metadata.json")
    }

    pub fn private_dir(&self) -> PathBuf {
        self.root.join("private")
    }

    pub fn public_dir(&self) -> PathBuf {
        self.root.join("public")
    }

    pub fn fingerprint_private_path(&self, fingerprint: &str) -> PathBuf {
        self.private_dir().join(format!("{}.age", fingerprint))
    }

    pub fn fingerprint_public_path(&self, fingerprint: &str) -> PathBuf {
        self.public_dir().join(format!("{}.pub", fingerprint))
    }
}
