use crate::domain::error::{AccountError, Result};

pub fn validate_user_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AccountError::InvalidUserId {
            reason: "Name cannot be empty".into(),
        });
    }
    if trimmed.len() < 2 {
        return Err(AccountError::InvalidUserId {
            reason: format!("Name too short: {} chars, minimum 2", trimmed.len()),
        });
    }
    if trimmed.len() > 255 {
        return Err(AccountError::InvalidUserId {
            reason: format!("Name too long: {} chars, maximum 255", trimmed.len()),
        });
    }
    for (i, c) in trimmed.char_indices() {
        let valid =
            c.is_alphabetic() || c.is_numeric() || c == ' ' || c == '-' || c == '\'' || c == '.';
        if !valid {
            return Err(AccountError::InvalidUserId {
                reason: format!("Invalid character '{}' at position {} in name", c, i + 1),
            });
        }
    }
    Ok(())
}

pub fn validate_user_email(email: &str) -> Result<()> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err(AccountError::InvalidUserId {
            reason: "Email cannot be empty".into(),
        });
    }
    if trimmed.len() > 254 {
        return Err(AccountError::InvalidUserId {
            reason: format!("Email too long: {} chars, maximum 254", trimmed.len()),
        });
    }
    let at_count = trimmed.chars().filter(|&c| c == '@').count();
    if at_count != 1 {
        return Err(AccountError::InvalidUserId {
            reason: "Email must contain exactly one '@'".into(),
        });
    }
    let parts: Vec<&str> = trimmed.split('@').collect();
    if parts[0].is_empty() || parts[1].is_empty() {
        return Err(AccountError::InvalidUserId {
            reason: "Email local part or domain is empty".into(),
        });
    }
    for (i, c) in trimmed.char_indices() {
        let valid = c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '@' || c == '+';
        if !valid {
            return Err(AccountError::InvalidUserId {
                reason: format!("Invalid character '{}' at position {} in email", c, i + 1),
            });
        }
    }
    Ok(())
}
