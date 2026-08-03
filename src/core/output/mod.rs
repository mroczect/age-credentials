//! Output formatting and serialization utilities.
//!
//! This module provides utilities for encoding and decoding data in various
//! formats commonly used for representing key material and metadata.
//! It is divided into three submodules, each handling a specific format:
//!
//! - [`ascii`]: Hexadecimal encoding and decoding (hex).
//! - [`json`]: JSON serialization and deserialization.
//! - [`toml`]: TOML serialization and deserialization.
//!
//! # Submodules
//! - **ascii**: Contains `hex_encode` and `hex_decode` for converting between
//!   byte arrays and hexadecimal strings. This is useful for displaying
//!   fingerprints or raw key bytes in a human‑readable form.
//! - **json**: Provides `to_json_pretty` and `from_json` for working with JSON.
//! - **toml**: Provides `to_toml_pretty` and `from_toml` for working with TOML.
//!
//! # Re‑exports
//! All public items from each submodule are re‑exported at this module level.
//! This means you can import them directly from `age_credentials::core::output`
//! without needing to reference the submodule names.
//!
//! # Example
//! ```
//! use age_credentials::core::output::{hex_encode, hex_decode, to_json_pretty};
//!
//! // Hex encoding
//! let bytes = vec![0xde, 0xad, 0xbe, 0xef];
//! let hex = hex_encode(&bytes);
//! assert_eq!(hex, "deadbeef");
//! let decoded = hex_decode(&hex).unwrap();
//! assert_eq!(decoded, bytes);
//!
//! // JSON serialization
//! use serde::Serialize;
//! #[derive(Serialize)]
//! struct Data { key: String }
//! let json = to_json_pretty(&Data { key: "value".into() })?;
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

pub mod ascii;
pub mod json;
pub mod toml;

pub use ascii::*;
pub use json::*;
pub use toml::*;
