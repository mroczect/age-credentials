//! ASCII and hexadecimal encoding/decoding utilities.
//!
//! This module provides functions to convert between byte arrays and their
//! hexadecimal string representations. The hex encoder produces lower‑case
//! hex digits, while the decoder accepts both upper‑ and lower‑case letters.
//!
//! # Examples
//! ```
//! use age_credentials::core::output::hex_encode;
//! use age_credentials::core::output::hex_decode;
//!
//! let data = vec![0xde, 0xad, 0xbe, 0xef];
//! let hex = hex_encode(&data);
//! assert_eq!(hex, "deadbeef");
//!
//! let decoded = hex_decode(&hex).unwrap();
//! assert_eq!(decoded, data);
//! ```

use crate::handler::error::{AgeCredentialsError, Result};
use std::fmt::Write;

/// Encodes a byte slice into a hexadecimal string.
///
/// Each byte is converted to two lower‑case hexadecimal digits. The output
/// string has exactly `data.len() * 2` characters.
///
/// # Arguments
/// * `data` – The byte slice to encode.
///
/// # Returns
/// A `String` containing the hex representation.
///
/// # Example
/// ```
/// # use age_credentials::core::output::hex_encode;
/// assert_eq!(hex_encode(&[0x01, 0x02, 0xff]), "0102ff");
/// ```
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(&mut s, "{:02x}", byte).unwrap();
    }
    s
}

/// Decodes a hexadecimal string into a byte vector.
///
/// The input string is trimmed of leading/trailing whitespace and must contain
/// an even number of characters. Both upper‑ and lower‑case hexadecimal digits
/// are accepted.
///
/// # Arguments
/// * `hex` – The hexadecimal string to decode.
///
/// # Errors
/// Returns `AgeCredentialsError::InvalidData` in the following cases:
/// - The input string is empty.
/// - The length of the trimmed string is odd.
/// - Any character is not a valid hexadecimal digit.
///
/// # Example
/// ```
/// # use age_credentials::core::output::hex_decode;
/// let bytes = hex_decode("deadbeef").unwrap();
/// assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
/// ```
pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "hex decode",
            details: "Input string is empty".into(),
        });
    }
    if !hex.len().is_multiple_of(2) {
        return Err(AgeCredentialsError::InvalidData {
            context: "hex decode",
            details: format!("Input length {} is odd, must be even", hex.len()),
        });
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_val(chunk[0]).map_err(|_| AgeCredentialsError::InvalidData {
            context: "hex decode",
            details: format!(
                "Invalid hex character '{}' at position {}",
                chunk[0] as char,
                i * 2
            ),
        })?;
        let low = hex_char_to_val(chunk[1]).map_err(|_| AgeCredentialsError::InvalidData {
            context: "hex decode",
            details: format!(
                "Invalid hex character '{}' at position {}",
                chunk[1] as char,
                i * 2 + 1
            ),
        })?;
        bytes.push(high << 4 | low);
    }
    Ok(bytes)
}

/// Converts a single ASCII character to its hexadecimal value (0‑15).
///
/// Supports digits `0`–`9`, letters `a`–`f`, and `A`–`F`.
///
/// # Arguments
/// * `c` – The ASCII byte to convert.
///
/// # Returns
/// `Ok(u8)` with the value if the character is valid, otherwise `Err(())`.
fn hex_char_to_val(c: u8) -> std::result::Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}
