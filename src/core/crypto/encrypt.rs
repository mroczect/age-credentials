use crate::handler::error::{AgeCredentialsError, Result};

pub fn encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    if public_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypt",
            details: "public key is empty".into(),
        });
    }
    let response = librage::encrypt(plaintext, public_key);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: vec![public_key.to_owned()],
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
            recipients: vec![public_key.to_owned()],
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}

pub fn encrypt_multiple(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>> {
    if public_keys.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypt multiple",
            details: "at least one public key required".into(),
        });
    }
    let response = librage::encrypt_multiple(plaintext, public_keys);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: public_keys.iter().map(|s| s.to_string()).collect(),
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
            recipients: public_keys.iter().map(|s| s.to_string()).collect(),
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}
