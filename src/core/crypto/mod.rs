//! Cryptographic operations for Age encryption.
//!
//! This module is the heart of the cryptographic functionality in the
//! age-credentials crate. It provides a comprehensive set of operations for
//! encrypting and decrypting data using the Age encryption format, including
//! support for both public-key and passphrase-based encryption.
//!
//! # Submodules
//!
//! - [`armor`]: ASCII‑armored encryption, producing human‑readable ciphertext
//!   suitable for text‑based contexts.
//! - [`decrypt`]: Decryption of binary ciphertext using a secret key.
//! - [`encrypt`]: Binary encryption using one or more public keys.
//! - [`keygen`]: Generation of new Age X25519 key pairs.
//! - [`passphrase`]: Passphrase-based encryption and decryption (no key pairs).
//! - [`recipient`]: Reading lists of recipients (public keys) from a file.
//!
//! # Re‑exports
//! For convenience, all public items from each submodule are re‑exported at
//! this module level. This means you can import cryptographic functions
//! directly from `age_credentials::core::crypto` without needing to reference
//! the submodule names.
//!
//! # Security
//! - Secret keys are handled with care: the `keygen` module returns secret
//!   keys wrapped in [`Zeroizing`] to ensure they are cleared from memory.
//! - Passphrase-based encryption requires a minimum passphrase length of
//!   8 characters to discourage weak passphrases.
//! - All cryptographic operations delegate to the `librage` library, which
//!   implements the Age specification.
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::{
//!     generate_keypair,
//!     encrypt,
//!     decrypt,
//!     encrypt_with_passphrase,
//!     decrypt_with_passphrase,
//! };
//!
//! // Generate a key pair
//! let keypair = generate_keypair()?;
//!
//! // Encrypt with a public key
//! let ciphertext = encrypt(b"secret message", &keypair.public_key)?;
//! let decrypted = decrypt(&ciphertext, &keypair.secret_key)?;
//! assert_eq!(decrypted, b"secret message");
//!
//! // Encrypt with a passphrase
//! let passphrase = "secure-passphrase";
//! let ciphertext = encrypt_with_passphrase(b"secret", passphrase)?;
//! let decrypted = decrypt_with_passphrase(&ciphertext, passphrase)?;
//! assert_eq!(decrypted, b"secret");
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

pub mod armor;
pub mod decrypt;
pub mod encrypt;
pub mod keygen;
pub mod passphrase;
pub mod recipient;

pub use armor::*;
pub use decrypt::*;
pub use encrypt::*;
pub use keygen::*;
pub use passphrase::*;
pub use recipient::*;
