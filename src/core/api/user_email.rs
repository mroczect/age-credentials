use crate::handler::error::{AgeCredentialsError, Result};

pub fn validate_user_email(email: &str) -> Result<()> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Email cannot be empty".into(),
        });
    }
    if trimmed.len() > 254 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: format!("Email too long: {} chars, maximum 254", trimmed.len()),
        });
    }
    let at_count = trimmed.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Email must contain exactly one '@'".into(),
        });
    }
    let parts: Vec<&str> = trimmed.split('@').collect();
    if parts[0].is_empty() || parts[1].is_empty() {
        return Err(AgeCredentialsError::InvalidUserId {
            reason: "Email local part or domain is empty".into(),
        });
    }
    for (i, c) in trimmed.char_indices() {
        let valid = c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '@' || c == '+';
        if !valid {
            return Err(AgeCredentialsError::InvalidUserId {
                reason: format!("Invalid character '{}' at position {} in email", c, i + 1),
            });
        }
    }
    Ok(())
}
