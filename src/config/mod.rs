//! Configuration management for the keyring.
//!
//! This module provides the foundational building blocks for managing keyring
//! configuration, including the directory structure, metadata persistence,
//! and file path construction.
//!
//! # Submodules
//! - [`loader`]: Handles loading and saving the `metadata.json` file using
//!   atomic writes and size limits.
//! - [`path`]: Manages the keyring directory hierarchy, creates required
//!   subdirectories (`private/`, `public/`), and constructs file paths for
//!   individual key files.
//!
//! # Re‑exports
//! All public items from both submodules are re‑exported at this module level,
//! allowing direct access to `ConfigLoader`, `KeyringPath`, and their methods
//! without needing to reference the submodules separately.
//!
//! # Example
//! ```
//! use age_credentials::config::{ConfigLoader, KeyringPath};
//!
//! // Initialize a keyring directory
//! let keyring = KeyringPath::new("/path/to/keyring")?;
//!
//! // Load the metadata
//! let metadata = ConfigLoader::load(keyring.metadata_file())?;
//!
//! // Save updated metadata
//! ConfigLoader::save(keyring.metadata_file(), &metadata)?;
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

pub mod loader;
pub mod path;

pub use loader::*;
pub use path::*;
