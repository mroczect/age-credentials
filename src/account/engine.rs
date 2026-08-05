use crate::backend::traits::AccountBackend;
use crate::crypto::{decrypt_with_passphrase, encrypt, encrypt_with_passphrase, generate_keypair};
use crate::domain::error::{AccountError, Result};
use crate::domain::fingerprint::Fingerprint;
use crate::domain::identity::Identity;
use crate::domain::types::UserID;
use sha2::Digest;
use zeroize::Zeroizing;

pub struct AccountEngine;

impl AccountEngine {
    pub fn create_account(
        backend: &mut dyn AccountBackend,
        user_id: UserID,
        passphrase: &str,
        label: Option<String>,
    ) -> Result<Identity> {
        let key_data = generate_keypair().map_err(|e| AccountError::KeyGenFailed {
            reason: e.to_string(),
        })?;

        let fingerprint = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(key_data.public_key.as_bytes());
            let digest = hasher.finalize();
            let hex_digest = digest
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            Fingerprint::new(hex_digest)?
        };

        let encrypted_private =
            encrypt_with_passphrase(key_data.secret_key.as_bytes(), passphrase)?;

        let identity = Identity::new(fingerprint.clone(), user_id, key_data.public_key, label);
        backend.save_identity(&identity)?;

        backend.store_encrypted_private_key(&fingerprint, &encrypted_private)?;

        Ok(identity)
    }

    pub fn encrypt_for_account(
        backend: &dyn AccountBackend,
        fingerprint: &Fingerprint,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let identity = backend
            .load_identity(fingerprint)?
            .ok_or_else(|| AccountError::AccountNotFound(fingerprint.to_string()))?;
        let ciphertext = encrypt(plaintext, &identity.public_key)?;
        Ok(ciphertext)
    }

    pub fn decrypt_for_account(
        backend: &dyn AccountBackend,
        fingerprint: &Fingerprint,
        passphrase: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let encrypted_key = backend
            .load_encrypted_private_key(fingerprint)?
            .ok_or_else(|| AccountError::AccountNotFound(fingerprint.to_string()))?;

        let secret_key = decrypt_with_passphrase(&encrypted_key, passphrase)?;
        let secret_key_str =
            std::str::from_utf8(&secret_key).map_err(|_| AccountError::InvalidData {
                context: "secret key decryption",
                details: "Decrypted key is not valid UTF-8".into(),
            })?;

        let plaintext = crate::crypto::decrypt(ciphertext, secret_key_str)?;
        Ok(Zeroizing::new(plaintext))
    }

    pub fn export_account(
        backend: &dyn AccountBackend,
        fingerprint: &Fingerprint,
        passphrase: &str,
    ) -> Result<String> {
        let identity = backend
            .load_identity(fingerprint)?
            .ok_or_else(|| AccountError::AccountNotFound(fingerprint.to_string()))?;
        let encrypted_key = backend
            .load_encrypted_private_key(fingerprint)?
            .ok_or_else(|| AccountError::AccountNotFound(fingerprint.to_string()))?;

        let export_data = serde_json::json!({
            "identity": identity,
            "encrypted_private_key": encrypted_key.to_vec(),
        });

        let plaintext =
            serde_json::to_vec(&export_data).map_err(|e| AccountError::Serialization {
                source: Box::new(e),
            })?;

        let exported = encrypt_with_passphrase(&plaintext, passphrase)?;
        Ok(crate::crypto::hex_encode(&exported))
    }

    pub fn import_account(
        backend: &mut dyn AccountBackend,
        data: &str,
        passphrase: &str,
    ) -> Result<Identity> {
        let encrypted_bytes = crate::crypto::hex_decode(data)?;
        let json_bytes = decrypt_with_passphrase(&encrypted_bytes, passphrase)?;
        let export_data: serde_json::Value =
            serde_json::from_slice(&json_bytes).map_err(|e| AccountError::Serialization {
                source: Box::new(e),
            })?;

        let identity: Identity =
            serde_json::from_value(export_data["identity"].clone()).map_err(|e| {
                AccountError::Serialization {
                    source: Box::new(e),
                }
            })?;
        let encrypted_key: Vec<u8> =
            serde_json::from_value(export_data["encrypted_private_key"].clone()).map_err(|e| {
                AccountError::Serialization {
                    source: Box::new(e),
                }
            })?;

        backend.save_identity(&identity)?;
        backend.store_encrypted_private_key(&identity.fingerprint, &encrypted_key)?;
        Ok(identity)
    }

    pub fn change_passphrase(
        backend: &mut dyn AccountBackend,
        fingerprint: &Fingerprint,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<()> {
        let encrypted_key = backend
            .load_encrypted_private_key(fingerprint)?
            .ok_or_else(|| AccountError::AccountNotFound(fingerprint.to_string()))?;

        let secret_key = decrypt_with_passphrase(&encrypted_key, old_passphrase)?;
        let new_encrypted = encrypt_with_passphrase(&secret_key, new_passphrase)?;
        backend.store_encrypted_private_key(fingerprint, &new_encrypted)?;
        Ok(())
    }

    pub fn delete_account(
        backend: &mut dyn AccountBackend,
        fingerprint: &Fingerprint,
    ) -> Result<()> {
        backend.delete_identity(fingerprint)
    }

    pub fn find_by_email(backend: &dyn AccountBackend, email: &str) -> Result<Option<Identity>> {
        let fp = backend.find_by_email(email)?;
        if let Some(fp) = fp {
            backend.load_identity(&fp)
        } else {
            Ok(None)
        }
    }

    pub fn list_accounts(backend: &dyn AccountBackend) -> Result<Vec<Identity>> {
        let fingerprints = backend.list_fingerprints()?;
        let mut identities = Vec::new();
        for fp in fingerprints {
            if let Some(id) = backend.load_identity(&fp)? {
                identities.push(id);
            }
        }
        Ok(identities)
    }
}
