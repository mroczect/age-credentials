use crate::handler::error::{AgeCredentialsError, Result};

pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let response = librage::encrypt_with_passphrase(plaintext, passphrase);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::EncryptionFailed {
            recipients: vec!["<passphrase>".to_owned()],
            code: err.code,
            message: err.message,
        });
    }
    Ok(response.data.unwrap().ciphertext.to_vec())
}

pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let response = librage::decrypt_with_passphrase(ciphertext, passphrase);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::DecryptionFailed {
            identity: None,
            hint: "Check passphrase".into(),
            code: err.code,
            message: err.message,
        });
    }
    Ok(response.data.unwrap().plaintext.to_vec())
}
