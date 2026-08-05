use crate::domain::error::{AccountError, Result};

fn extract_armor_error(
    response: librage::LibrageResponse<librage::EncryptOutput>,
    recipients: Vec<String>,
) -> Result<Vec<u8>> {
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AccountError::EncryptionFailed {
                recipients: recipients.clone(),
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AccountError::EncryptionFailed {
            recipients,
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AccountError::EncryptionFailed {
            recipients,
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}

pub fn encrypt_armored(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    if public_key.is_empty() {
        return Err(AccountError::InvalidData {
            context: "armor encrypt",
            details: "public key is empty".into(),
        });
    }
    let response = librage::encrypt_armored(plaintext, public_key);
    extract_armor_error(response, vec![public_key.to_owned()])
}

pub fn encrypt_multiple_armored(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>> {
    if public_keys.is_empty() {
        return Err(AccountError::InvalidData {
            context: "armor encrypt multiple",
            details: "at least one public key required".into(),
        });
    }
    let response = librage::encrypt_multiple_armored(plaintext, public_keys);
    let recipients: Vec<String> = public_keys.iter().map(|s| s.to_string()).collect();
    extract_armor_error(response, recipients)
}
