//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
use crate::handler::error::{AgeCredentialsError, Result};
use serde::{Deserialize, Serialize};

/// #[derive(Serialize)]
pub fn to_json_pretty<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| AgeCredentialsError::Serialization {
        target: "json",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}

/// #[derive(Deserialize, PartialEq, Debug)]
pub fn from_json<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| AgeCredentialsError::Serialization {
        target: "json",
        path: std::path::PathBuf::from("<memory>"),
        source: Box::new(e),
    })
}
