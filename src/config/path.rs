//! Path management for the keyring directory structure.
//!
//! This module provides [`KeyringPath`], a wrapper around the root directory
//! of a keyring. It ensures that the required subdirectories (`private/` and
//! `public/`) exist and provides convenient methods to construct file paths
//! for the metadata file and individual key files.
//!
//! # Keyring Layout
//! The expected directory structure is:
//!
//! ```text
//! /keyring/root/
//! ├── metadata.json
//! ├── private/
//! │   ├── fingerprint1.age
//! │   └── fingerprint2.age
//! └── public/
//!     ├── fingerprint1.pub
//!     └── fingerprint2.pub
//! ```
//!
//! # Usage
//! ```
//! use age_credentials::config::KeyringPath;
//!
//! // Create a new keyring (directories are created automatically)
//! let keyring = KeyringPath::new("/path/to/keyring")?;
//!
//! // Or open an existing one
//! let existing = KeyringPath::open_existing("/path/to/keyring")?;
//!
//! // Get paths
//! let meta = keyring.metadata_file();
//! let priv_dir = keyring.private_dir();
//! let pub_dir = keyring.public_dir();
//! let priv_path = keyring.fingerprint_private_path("deadbeef");
//! let pub_path = keyring.fingerprint_public_path("deadbeef");
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use std::path::{Path, PathBuf};

/// A managed keyring directory with a known structure.
///
/// `KeyringPath` stores the canonicalized absolute path of the keyring root.
/// It guarantees that the `private/` and `public/` subdirectories exist when
/// created with `new`, and provides methods to generate paths for metadata
/// and key files.
///
/// # Fields
/// * `root` – The canonicalized absolute path of the keyring root directory.
#[derive(Debug, Clone)]
pub struct KeyringPath {
    root: PathBuf,
}

impl KeyringPath {
    /// Creates a new keyring at the given path.
    ///
    /// This function:
    /// 1. Validates that the path is not empty.
    /// 2. Creates the root directory and all parent directories if necessary.
    /// 3. Canonicalizes the path to an absolute form.
    /// 4. Creates the `private/` and `public/` subdirectories.
    ///
    /// # Arguments
    /// * `path` – The desired root directory.
    ///
    /// # Errors
    /// - `AgeCredentialsError::Config` – If the path is empty.
    /// - `AgeCredentialsError::Io` – For any filesystem error (creation,
    ///   canonicalization, or subdirectory creation).
    ///
    /// # Example
    /// ```
    /// # use age_credentials::config::KeyringPath;
    /// let keyring = KeyringPath::new("/tmp/my_keyring")?;
    /// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
    /// ```
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(AgeCredentialsError::Config {
                message: "Keyring path cannot be empty".into(),
                location: file!().to_string(),
            });
        }

        std::fs::create_dir_all(path).map_err(|e| AgeCredentialsError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let absolute = std::fs::canonicalize(path).map_err(|e| AgeCredentialsError::Io {
            path: path.to_path_buf(),
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

    /// Opens an existing keyring directory without creating it.
    ///
    /// This function checks that the path exists and is a directory, then
    /// canonicalizes it. It does **not** verify that the `private/` and
    /// `public/` subdirectories exist.
    ///
    /// # Arguments
    /// * `path` – The root directory of the keyring.
    ///
    /// # Errors
    /// - `AgeCredentialsError::Config` – If the path is not a directory.
    /// - `AgeCredentialsError::Io` – If canonicalization fails.
    ///
    /// # Example
    /// ```
    /// # use age_credentials::config::KeyringPath;
    /// let keyring = KeyringPath::open_existing("/tmp/my_keyring")?;
    /// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
    /// ```
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

    /// Returns the full path to the `metadata.json` file.
    ///
    /// This is the canonical location for the keyring’s metadata.
    pub fn metadata_file(&self) -> PathBuf {
        self.root.join("metadata.json")
    }

    /// Returns the full path to the `private/` subdirectory.
    pub fn private_dir(&self) -> PathBuf {
        self.root.join("private")
    }

    /// Returns the full path to the `public/` subdirectory.
    pub fn public_dir(&self) -> PathBuf {
        self.root.join("public")
    }

    /// Constructs the path to a private key file for the given fingerprint.
    ///
    /// The file name is `{fingerprint}.age` inside the `private/` directory.
    ///
    /// # Arguments
    /// * `fingerprint` – The fingerprint (typically a hex string).
    ///
    /// # Returns
    /// A `PathBuf` like `root/private/fingerprint.age`.
    pub fn fingerprint_private_path(&self, fingerprint: &str) -> PathBuf {
        self.private_dir().join(format!("{}.age", fingerprint))
    }

    /// Constructs the path to a public key file for the given fingerprint.
    ///
    /// The file name is `{fingerprint}.pub` inside the `public/` directory.
    ///
    /// # Arguments
    /// * `fingerprint` – The fingerprint (typically a hex string).
    ///
    /// # Returns
    /// A `PathBuf` like `root/public/fingerprint.pub`.
    pub fn fingerprint_public_path(&self, fingerprint: &str) -> PathBuf {
        self.public_dir().join(format!("{}.pub", fingerprint))
    }
}
