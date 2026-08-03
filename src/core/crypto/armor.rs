use crate::handler::error::{AgeCredentialsError, Result};

pub fn encrypt_armored(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    if public_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "armor encrypt",
            details: "public key is empty".into(),
        });
    }
    let response = librage::encrypt_armored(plaintext, public_key);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: vec![public_key.to_owned()],
            code: err.code,
            message: err.message,
        });
    }
    Ok(response.data.unwrap().ciphertext.to_vec())
}

pub fn encrypt_multiple_armored(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>> {
    if public_keys.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "armor encrypt multiple",
            details: "at least one public key required".into(),
        });
    }
    let response = librage::encrypt_multiple_armored(plaintext, public_keys);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: public_keys.iter().map(|s| s.to_string()).collect(),
            code: err.code,
            message: err.message,
        });
    }
    Ok(response.data.unwrap().ciphertext.to_vec())
}
