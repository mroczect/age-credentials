use crate::handler::error::{AgeCredentialsError, Result};
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn read_recipients_from_file(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let path = path.as_ref().to_path_buf();
    let file = std::fs::File::open(&path).map_err(|e| AgeCredentialsError::Io {
        path: path.clone(),
        source: e,
    })?;
    let reader = BufReader::new(file);
    let mut recipients = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| AgeCredentialsError::Io {
            path: path.clone(),
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
