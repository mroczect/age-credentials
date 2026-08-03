use crate::handler::error::{AgeCredentialsError, Result};
use std::fmt::Write;

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(&mut s, "{:02x}", byte).unwrap();
    }
    s
}

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

fn hex_char_to_val(c: u8) -> std::result::Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}
