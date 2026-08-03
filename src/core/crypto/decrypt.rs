use crate::handler::error::{AgeCredentialsError, Result};

pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>> {
    if secret_key.is_empty() {
        return Err(AgeCredentialsError::InvalidData {
            context: "decrypt",
            details: "secret key is empty".into(),
        });
    }
    let response = librage::decrypt(ciphertext, secret_key);
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AgeCredentialsError::DecryptionFailed {
                identity: None,
                hint: "librage returned failure without error details".into(),
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AgeCredentialsError::DecryptionFailed {
            identity: None,
            hint: "Verify secret key or ciphertext integrity".into(),
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::DecryptionFailed {
            identity: None,
            hint: "librage returned success but no data".into(),
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.plaintext.to_vec())
}
