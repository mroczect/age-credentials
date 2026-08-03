use crate::handler::error::{AgeCredentialsError, Result};

fn extract_encrypt_error(
    response: librage::LibrageResponse<librage::EncryptOutput>,
    recipients: Vec<String>,
) -> Result<Vec<u8>> {
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
                recipients: recipients.clone(),
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients,
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
            recipients,
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}

pub fn encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    if public_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypt",
            details: "public key is empty".into(),
        });
    }
    let response = librage::encrypt(plaintext, public_key);
    extract_encrypt_error(response, vec![public_key.to_owned()])
}

pub fn encrypt_multiple(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>> {
    if public_keys.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "encrypt multiple",
            details: "at least one public key required".into(),
        });
    }
    let response = librage::encrypt_multiple(plaintext, public_keys);
    let recipients: Vec<String> = public_keys.iter().map(|s| s.to_string()).collect();
    extract_encrypt_error(response, recipients)
}
