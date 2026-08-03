//! Age credentials management library.
//!
//! This crate provides a comprehensive, secure, and ergonomic API for managing
//! Age encryption credentials, including key generation, encryption,
//! decryption, keyring management, and metadata persistence.
//!
//! # Overview
//!
//! The `age-credentials` crate is built on top of the Age encryption
//! specification and the `librage` bindings. It is designed to handle
//! file-based keyrings, support multiple recipients, passphrase-based
//! encryption, and serialization of metadata in JSON or TOML formats.
//! All sensitive data is handled with care using zeroization.
//!
//! # Architecture
//!
//! The crate is organized into three main modules:
//!
//! - [`config`]: Configuration and file system management for the keyring.
//!   - Directory structure creation and validation.
//!   - Loading and saving metadata with atomic writes.
//!   - Path construction for key files.
//!
//! - [`core`]: Core cryptographic operations and I/O.
//!   - **api**: File I/O for reading/writing encrypted private keys and
//!     public keys.
//!   - **crypto**: Encryption, decryption, key generation, passphrase support,
//!     and recipient file parsing.
//!   - **output**: Hex, JSON, and TOML serialization utilities.
//!
//! - [`handler`]: Error handling and core data types.
//!   - **[`error`]**: Comprehensive `AgeCredentialsError` enum.
//!   - **[`types`]**: `Fingerprint`, `UserID`, `Identity`, `Metadata`,
//!     `KeyGenData`.
//!
//! # Security
//!
//! - Secret keys are stored in [`Zeroizing`] wrappers to ensure they are
//!   securely cleared from memory when dropped.
//! - Metadata writes are performed atomically using temporary files to prevent
//!   corruption.
//! - A maximum file size of 5 MB is enforced for metadata files.
//! - Passphrase-based encryption requires a minimum passphrase length of
//!   8 characters.
//! - All cryptographic operations delegate to the `librage` library.
//!
//! # Example
//!
//! ```no_run
//! use age_credentials::{
//!     config::KeyringPath,
//!     core::{
//!         generate_keypair,
//!         encrypt,
//!         decrypt,
//!         write_public_key,
//!         write_encrypted_private_key,
//!     },
//!     handler::{
//!         Metadata,
//!         Identity,
//!         UserID,
//!         Fingerprint,
//!     },
//! };
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! # fn main() -> Result<(), age_credentials::handler::error::AgeCredentialsError> {
//! // 1. Initialize the keyring directory
//! let keyring = KeyringPath::new("/path/to/keyring")?;
//!
//! // 2. Generate a new key pair
//! let keypair = generate_keypair()?;
//!
//! // 3. Create a fingerprint from the public key
//! // (In practice, you'd derive this from the key; here we use a placeholder)
//! let fingerprint = Fingerprint::new("deadbeef")?;
//!
//! // 4. Write the keys to files
//! let priv_path = keyring.fingerprint_private_path(&fingerprint.to_string());
//! let pub_path = keyring.fingerprint_public_path(&fingerprint.to_string());
//! write_encrypted_private_key(&priv_path, b"encrypted-key-bytes")?;
//! write_public_key(&pub_path, &keypair.public_key)?;
//!
//! // 5. Create an identity
//! let user_id = UserID::new("Alice Example", "alice@example.com")?;
//! let identity = Identity {
//!     fingerprint: fingerprint.clone(),
//!     user_id,
//!     label: Some("Personal key".into()),
//!     private_key_path: priv_path,
//!     public_key_path: pub_path,
//!     created_at: SystemTime::now()
//!         .duration_since(UNIX_EPOCH)
//!         .unwrap()
//!         .as_secs() as i64,
//! };
//!
//! // 6. Build metadata
//! let mut metadata = Metadata::default();
//! metadata.identities.push(identity);
//! metadata.default_identity = Some(fingerprint);
//!
//! // 7. Save metadata (atomically)
//! age_credentials::config::ConfigLoader::save(keyring.metadata_file(), &metadata)?;
//!
//! // 8. Encrypt a message
//! let plaintext = b"Hello, world!";
//! let ciphertext = encrypt(plaintext, &keypair.public_key)?;
//!
//! // 9. Decrypt the message
//! let decrypted = decrypt(&ciphertext, &keypair.secret_key)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - **Key generation**: Create new Age X25519 key pairs.
//! - **Encryption**: Binary and ASCII‑armored encryption with single or
//!   multiple recipients.
//! - **Decryption**: Decrypt with a secret key or passphrase.
//! - **Passphrase support**: Encrypt and decrypt with a passphrase.
//! - **Keyring management**: Organize identities in a directory structure.
//! - **Metadata persistence**: Save and load metadata in JSON format.
//! - **Data formatting**: Hex, JSON, and TOML encoding/decoding.
//! - **Error handling**: Comprehensive, typed errors for all operations.
//! - **Zeroization**: Secure clearing of sensitive data.
//!
//! # Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`config`] | Keyring configuration, metadata persistence, path management |
//! | [`core`]   | Cryptographic operations, key I/O, data formatting |
//! | [`handler`] | Error types and core data structures |
//!
//! # Re‑exports
//!
//! For convenience, all public items from each module are re‑exported at the
//! root level. You can import everything you need directly from
//! `age_credentials`:
//!
//! ```
//! use age_credentials::{
//!     ConfigLoader,
//!     KeyringPath,
//!     generate_keypair,
//!     encrypt,
//!     decrypt,
//!     Metadata,
//!     Identity,
//!     Fingerprint,
//!     UserID,
//!     AgeCredentialsError,
//!     Result,
//! };
//! ```
//!
//! # See Also
//!
//! - [Age encryption specification](https://age-encryption.org/v1)
//! - [`librage`](https://crates.io/crates/librage) – Rust bindings for age
//! - [The Rust Book](https://doc.rust-lang.org/book/) – Learning Rust

pub mod config;
pub mod core;
pub mod handler;

pub use config::*;
pub use core::*;
pub use handler::*;
