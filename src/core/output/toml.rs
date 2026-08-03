//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
use crate::handler::error::{AgeCredentialsError, Result};
use serde::{Deserialize, Serialize};

/// #[derive(Serialize)]
pub fn to_toml_pretty<T: Serialize>(value: &T) -> Result<String> {
    toml::to_string_pretty(value).map_err(|e| AgeCredentialsError::Serialization {
        target: "toml",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}

/// #[derive(Deserialize, PartialEq, Debug)]
pub fn from_toml<T: for<'de> Deserialize<'de>>(toml_str: &str) -> Result<T> {
    toml::from_str(toml_str).map_err(|e| AgeCredentialsError::Serialization {
        target: "toml",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}
