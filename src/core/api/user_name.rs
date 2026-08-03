use crate::handler::error::{AgeCredentialsError, Result};

pub fn validate_user_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Name cannot be empty".into(),
        });
    }
    if trimmed.len() < 2 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: format!("Name too short: {} chars, minimum 2", trimmed.len()),
        });
    }
    if trimmed.len() > 255 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: format!("Name too long: {} chars, maximum 255", trimmed.len()),
        });
    }
    for (i, c) in trimmed.char_indices() {
        let valid =
            c.is_alphabetic() || c.is_numeric() || c == ' ' || c == '-' || c == '\'' || c == '.';
        if !valid {
            return Err(AgeCredentialsError::InvalidUserId {
                reason: format!("Invalid character '{}' at position {} in name", c, i + 1),
            });
        }
    }
    Ok(())
}
