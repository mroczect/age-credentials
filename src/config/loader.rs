//! Loading and saving of keyring metadata.
//!
//! This module provides the [`ConfigLoader`] type, which handles reading and
//! writing the `metadata.json` file that stores all identities and the default
//! identity fingerprint.
//!
//! # Security
//! - A maximum file size of 5 MB is enforced to prevent denial‑of‑service
//!   through memory exhaustion.
//! - Writes are performed atomically using a temporary file, ensuring that
//!   the metadata file is never left in a partially written state.
//!
//! # Usage
//! ```
//! use age_credentials::config::ConfigLoader;
//! # use age_credentials::handler::types::Metadata;
//! # let path = "metadata.json";
//! # let metadata = Metadata::default();
//! let loaded = ConfigLoader::load(path)?;
//! ConfigLoader::save(path, &metadata)?;
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use crate::handler::types::Metadata;
use std::path::Path;

/// The maximum allowed size (5 MiB) for the metadata file.
const MAX_METADATA_SIZE: usize = 5 * 1024 * 1024;

/// A stateless utility for loading and saving keyring metadata.
///
/// This struct provides only static methods; it has no state and cannot be
/// instantiated.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Loads and deserializes metadata from a JSON file.
    ///
    /// # Arguments
    /// * `path` – The file path to read from.
    ///
    /// # Behavior
    /// 1. Reads the entire file into a `String`.
    /// 2. Checks that the file size does not exceed [`MAX_METADATA_SIZE`].
    /// 3. Parses the JSON content into a [`Metadata`] struct.
    ///
    /// # Errors
    /// Returns an error in the following cases:
    /// - `AgeCredentialsError::Io` – If reading the file fails.
    /// - `AgeCredentialsError::InvalidData` – If the file exceeds the size limit.
    /// - `AgeCredentialsError::Serialization` – If the JSON is malformed.
    ///
    /// # Example
    /// ```
    /// # use age_credentials::config::ConfigLoader;
    /// # let path = "metadata.json";
    /// let metadata = ConfigLoader::load(path)?;
    /// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
    /// ```
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
                path: path.clone(),
                source: Box::new(e),
            })?;
        Ok(metadata)
    }

    /// Serializes and atomically saves metadata to a JSON file.
    ///
    /// # Arguments
    /// * `path` – The target file path.
    /// * `metadata` – The metadata to write.
    ///
    /// # Behavior
    /// 1. Serializes the metadata to pretty‑printed JSON.
    /// 2. Determines the parent directory of the target path.
    /// 3. Creates a temporary file in that parent directory.
    /// 4. Writes the JSON data to the temporary file.
    /// 5. Atomically persists the temporary file to the target path
    ///    (overwriting any existing file).
    ///
    /// # Errors
    /// Returns an error in the following cases:
    /// - `AgeCredentialsError::Serialization` – If serialization fails.
    /// - `AgeCredentialsError::Config` – If the target path has no parent directory.
    /// - `AgeCredentialsError::Io` – For any filesystem error during creation,
    ///   writing, or persistence of the temporary file.
    ///
    /// # Example
    /// ```
    /// # use age_credentials::config::ConfigLoader;
    /// # use age_credentials::handler::types::Metadata;
    /// # let path = "metadata.json";
    /// # let metadata = Metadata::default();
    /// ConfigLoader::save(path, &metadata)?;
    /// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
    /// ```
    pub fn save(path: impl AsRef<Path>, metadata: &Metadata) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        let json = serde_json::to_string_pretty(metadata).map_err(|e| {
            AgeCredentialsError::Serialization {
                target: "metadata",
                path: path.clone(),
                source: Box::new(e),
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
