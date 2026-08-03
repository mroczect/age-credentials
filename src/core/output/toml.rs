//! TOML serialization and deserialization utilities.
//!
//! This module provides convenience functions for converting values to and from
//! TOML format using the `toml` crate. The serialization produces pretty‑printed
//! (indented) TOML for human readability.
//!
//! # Errors
//! All functions return `AgeCredentialsError::Serialization` on failure, with
//! the target set to `"toml"` and the path set to `<memory>` (since the data is
//! not file‑based).
//!
//! # Example
//! ```
//! use age_credentials::core::output::{to_toml_pretty, from_toml};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct MyData {
//!     name: String,
//!     age: u8,
//! }
//!
//! let data = MyData { name: "Bob".into(), age: 25 };
//! let toml = to_toml_pretty(&data)?;
//! let parsed: MyData = from_toml(&toml)?;
//! assert_eq!(parsed, data);
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use serde::{Deserialize, Serialize};

/// Serializes a value to a pretty‑printed TOML string.
///
/// The output is formatted with indentation for readability.
///
/// # Arguments
/// * `value` – Any value that implements `serde::Serialize`.
///
/// # Errors
/// Returns `AgeCredentialsError::Serialization` if serialization fails.
///
/// # Example
/// ```
/// # use age_credentials::core::output::to_toml_pretty;
/// # use serde::Serialize;
/// #[derive(Serialize)]
/// struct Foo { bar: i32 }
/// let toml = to_toml_pretty(&Foo { bar: 42 })?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn to_toml_pretty<T: Serialize>(value: &T) -> Result<String> {
    toml::to_string_pretty(value).map_err(|e| AgeCredentialsError::Serialization {
        target: "toml",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}

/// Deserializes a TOML string into a value of type `T`.
///
/// # Arguments
/// * `toml_str` – A valid TOML string.
///
/// # Errors
/// Returns `AgeCredentialsError::Serialization` if parsing fails.
///
/// # Example
/// ```
/// # use age_credentials::core::output::from_toml;
/// # use serde::Deserialize;
/// #[derive(Deserialize, PartialEq, Debug)]
/// struct Foo { bar: i32 }
/// let foo: Foo = from_toml(r#"bar = 42"#)?;
/// assert_eq!(foo.bar, 42);
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn from_toml<T: for<'de> Deserialize<'de>>(toml_str: &str) -> Result<T> {
    toml::from_str(toml_str).map_err(|e| AgeCredentialsError::Serialization {
        target: "toml",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}
