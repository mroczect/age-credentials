//! High-level file I/O for Age keys.
//!
//! This module provides the foundational functions for reading and writing
//! Age key material to the filesystem. It is split into two submodules,
//! one for encrypted private keys and one for public keys, but all relevant
//! functions are re‑exported at this module level for convenience.
//!
//! # Security
//! - Private key data is read into a [`Zeroizing`] buffer to ensure it is
//!   securely cleared from memory when dropped.
//! - Public keys are validated as proper `age::x25519::Recipient` strings
//!   before they are returned or written.
//!
//! # Submodules
//! - [`private_keys`]: Operations on encrypted private key files (`.age`).
//! - [`public_keys`]: Operations on public key files (`.pub`).
//!
//! # Re‑exports
//! All public items from both submodules are re‑exported at this level, so you
//! can call them directly from `age_credentials::core::api`.
//!
//! # Example
//! ```
//! use age_credentials::core::api::{
//!     read_encrypted_private_key,
//!     write_encrypted_private_key,
//!     read_public_key,
//!     write_public_key,
//! };
//!
//! // Write a public key
//! write_public_key("key.pub", "age1...")?;
//!
//! // Read it back
//! let pub_key = read_public_key("key.pub")?;
//!
//! // Write an encrypted private key
//! write_encrypted_private_key("key.age", &[0x01, 0x02, 0x03])?;
//!
//! // Read it back into a zeroizing buffer
//! let priv_key = read_encrypted_private_key("key.age")?;
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

pub mod private_keys;
pub mod public_keys;

pub use private_keys::*;
pub use public_keys::*;
