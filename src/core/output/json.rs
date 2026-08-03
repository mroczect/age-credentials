//! JSON serialization and deserialization utilities.
//!
//! This module provides convenience functions for converting values to and from
//! JSON format using `serde_json`. The serialization produces pretty‑printed
//! (indented) JSON for human readability.
//!
//! # Errors
//! All functions return `AgeCredentialsError::Serialization` on failure, with
//! the target set to `"json"` and the path set to `<memory>` (since the data
//! is not file‑based).
//!
//! # Example
//! ```
//! use age_credentials::core::output::{to_json_pretty, from_json};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct MyData {
//!     name: String,
//!     age: u8,
//! }
//!
//! let data = MyData { name: "Alice".into(), age: 30 };
//! let json = to_json_pretty(&data)?;
//! let parsed: MyData = from_json(&json)?;
//! assert_eq!(parsed, data);
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use serde::{Deserialize, Serialize};

/// Serializes a value to a pretty‑printed JSON string.
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
/// # use age_credentials::core::output::to_json_pretty;
/// # use serde::Serialize;
/// #[derive(Serialize)]
/// struct Foo { bar: i32 }
/// let json = to_json_pretty(&Foo { bar: 42 })?;
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn to_json_pretty<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| AgeCredentialsError::Serialization {
        target: "json",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}

/// Deserializes a JSON string into a value of type `T`.
///
/// # Arguments
/// * `json` – A valid JSON string.
///
/// # Errors
/// Returns `AgeCredentialsError::Serialization` if parsing fails.
///
/// # Example
/// ```
/// # use age_credentials::core::output::from_json;
/// # use serde::Deserialize;
/// #[derive(Deserialize, PartialEq, Debug)]
/// struct Foo { bar: i32 }
/// let foo: Foo = from_json(r#"{"bar":42}"#)?;
/// assert_eq!(foo.bar, 42);
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn from_json<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| AgeCredentialsError::Serialization {
        target: "json",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}
