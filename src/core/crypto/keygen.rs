use crate::handler::error::{AgeCredentialsError, Result};
use crate::handler::types::KeyGenData;

pub fn generate_keypair() -> Result<KeyGenData> {
    let response = librage::generate_keypair();
    if !response.success {
        let reason = match response.error {
            Some(e) => format!("{}: {}", e.code, e.message),
            None => "Unknown librage error".to_string(),
        };
        return Err(AgeCredentialsError::KeyGenFailed { reason });
    }
    let data = response
        .data
        .ok_or_else(|| AgeCredentialsError::KeyGenFailed {
            reason: "librage returned success but no data".into(),
        })?;
    Ok(KeyGenData {
        public_key: data.public_key,
        secret_key: data.secret_key,
    })
}
