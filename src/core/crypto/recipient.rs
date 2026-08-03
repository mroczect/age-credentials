//! Reading recipient (public key) lists from a file.
//!
//! This module provides a function to read one or more Age public keys from
//! a text file. The file is expected to contain one public key per line, with
//! optional blank lines and comments (lines starting with `#`). Each key is
//! validated to start with the prefix `"age"`, which is characteristic of all
//! Age X25519 public keys.
//!
//! # File Format
//! ```text
//! # This is a comment
//! age1...
//! age1...
//!
//! # Another comment
//! age1...
//! ```
//!
//! # Example
//! ```
//! use age_credentials::core::crypto::read_recipients_from_file;
//! let recipients = read_recipients_from_file("recipients.txt")?;
//! for key in &recipients {
//!     println!("{}", key);
//! }
//! # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Reads a list of Age public keys from a file.
///
/// The file is read line by line. Empty lines and lines starting with `#` are
/// ignored. Each non‑empty, non‑comment line is trimmed of whitespace and must
/// start with the `"age"` prefix. All valid lines are collected into a `Vec<String>`.
///
/// # Arguments
/// * `path` – The path to the recipient file.
///
/// # Returns
/// A vector of public key strings, in the order they appear in the file.
///
/// # Errors
/// - `AgeCredentialsError::Io` – If the file cannot be opened or read.
/// - `AgeCredentialsError::InvalidData` – If:
///   - A line does not start with `"age"`.
///   - No valid recipients are found (the file is empty or contains only
///     comments/blank lines).
///
/// # Example
/// ```
/// # use age_credentials::core::crypto::read_recipients_from_file;
/// # let path = "recipients.txt";
/// let recipients = read_recipients_from_file(path)?;
/// assert!(!recipients.is_empty());
/// # Ok::<_, age_credentials::handler::error::AgeCredentialsError>(())
/// ```
pub fn read_recipients_from_file(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let path = path.as_ref();
    let file = std::fs::File::open(path).map_err(|e| AgeCredentialsError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let reader = BufReader::new(file);
    let mut recipients = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| AgeCredentialsError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.starts_with("age") {
            return Err(AgeCredentialsError::InvalidData {
                context: "recipient file",
                details: format!(
                    "Line {} does not look like an age public key: {}",
                    line_no + 1,
                    trimmed
                ),
            });
        }
        recipients.push(trimmed.to_owned());
    }

    if recipients.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "recipient file",
            details: "No valid recipient found in file".into(),
        });
    }
    Ok(recipients)
}
