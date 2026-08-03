use crate::handler::error::{AgeCredentialsError, Result};

const MIN_PASSPHRASE_LEN: usize = 8;

pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(AgeCredentialsError::PassphraseTooShort {
            length: passphrase.len(),
            min_length: MIN_PASSPHRASE_LEN,
        });
    }
    let response = librage::encrypt_with_passphrase(plaintext, passphrase);
    if !response.success {
        let err = response
            .error
            .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
                recipients: vec!["<passphrase>".to_owned()],
                code: "UNKNOWN".into(),
                message: "librage returned failure without error details".into(),
            })?;
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: vec!["<passphrase>".to_owned()],
            code: err.code,
            message: err.message,
        });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::EncryptionFailed {
            recipients: vec!["<passphrase>".to_owned()],
            code: "UNKNOWN".into(),
            message: "librage returned success but no data".into(),
        })?;
    Ok(data.ciphertext.to_vec())
}

pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(AgeCredentialsError::PassphraseTooShort {
            length: passphrase.len(),
            min_length: MIN_PASSPHRASE_LEN,
        });
    }
    let response = librage::decrypt_with_passphrase(ciphertext, passphrase);
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
            hint: "Check passphrase".into(),
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
