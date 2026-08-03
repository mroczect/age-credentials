//! Core cryptographic and I/O operations for Age credentials.
//!
//! This module is the central component of the age-credentials crate,
//! providing the essential building blocks for working with Age encryption.
//! It is organized into three primary submodules that handle different
//! aspects of cryptographic key management, encryption/decryption, and
//! data formatting.
//!
//! # Architecture
//!
//! ```text
//! core/
//! ├── api/        – High-level file I/O for keys (reading/writing files)
//! ├── crypto/     – Cryptographic operations (encrypt, decrypt, keygen)
//! └── output/     – Data formatting and serialization (hex, JSON, TOML)
//! ```
//!
//! # Submodules
//!
//! - [`api`]: File-based operations for reading and writing encrypted private
//!   keys (`.age` files) and public keys (`.pub` files). These functions
//!   interact directly with the filesystem and handle validation.
//!
//! - [`crypto`]: The core cryptographic operations, including:
//!   - Binary encryption with one or more public keys.
//!   - ASCII‑armored encryption for human‑readable output.
//!   - Decryption using a secret key.
//!   - Passphrase‑based encryption and decryption.
//!   - Key pair generation.
//!   - Reading recipient lists from files.
//!
//! - [`output`]: Utilities for encoding and decoding data in various formats:
//!   - Hexadecimal encoding/decoding (for fingerprints and raw bytes).
//!   - JSON serialization/deserialization (pretty‑printed).
//!   - TOML serialization/deserialization (pretty‑printed).
//!
//! # Re‑exports
//! For convenience, all public items from each submodule are re‑exported at
//! this module level. This allows you to access the entire core functionality
//! directly from `age_credentials::core` without needing to reference the
//! submodules individually.
//!
//! # Example
//! ```
//! use age_credentials::core::{
//!     // From api
//!     read_public_key,
//!     write_public_key,
//!     // From crypto
//!     generate_keypair,
//!     encrypt,
//!     decrypt,
//!     // From output
//!     hex_encode,
//!     to_json_pretty,
//! };
//!
//! // Generate a key pair
//! let keypair = generate_keypair()?;
//!
//! // Encrypt some data
//! let ciphertext = encrypt(b"secret", &keypair.public_key)?;
//!
//! // Decrypt it
//! let plaintext = decrypt(&ciphertext, &keypair.secret_key)?;
//! assert_eq!(plaintext, b"secret");
//!
//! // Encode the fingerprint as hex
//! let fingerprint = hex_encode(&[0xde, 0xad, 0xbe, 0xef]);
//! assert_eq!(fingerprint, "deadbeef");
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```
//!
//! # Security
//! The `core` module is designed with security in mind:
//! - Secret keys returned from `keygen` are wrapped in [`Zeroizing`] to
//!   ensure they are cleared from memory.
//! - All cryptographic operations delegate to the `librage` library, which
//!   provides a safe implementation of the Age specification.
//! - File operations are careful about error handling and do not leak
//!   sensitive information through error messages.

pub mod api;
pub mod crypto;
pub mod output;

pub use api::*;
pub use crypto::*;
pub use output::*;
