use crate::handler::error::{AgeCredentialsError, Result};

pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>> {
    let response = librage::decrypt(ciphertext, secret_key);
    if !response.success {
        let err = response.error.expect("error field missing");
        return Err(AgeCredentialsError::DecryptionFailed {
            identity: None,
            hint: "Verify secret key or ciphertext integrity".into(),
            code: err.code,
            message: err.message,
        });
    }
    Ok(response.data.unwrap().plaintext.to_vec())
}
