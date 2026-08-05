use age_credentials::account::AccountEngine;
use age_credentials::backend::traits::AccountBackend;
use age_credentials::domain::error::Result;
use age_credentials::domain::fingerprint::Fingerprint;
use age_credentials::domain::identity::Identity;
use age_credentials::domain::types::UserID;
use std::collections::HashMap;
use zeroize::Zeroizing;

struct MockBackend {
    identities: HashMap<String, Identity>,
    private_keys: HashMap<String, Vec<u8>>,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            identities: HashMap::new(),
            private_keys: HashMap::new(),
        }
    }
}

impl AccountBackend for MockBackend {
    fn save_identity(&mut self, identity: &Identity) -> Result<()> {
        self.identities
            .insert(identity.fingerprint.to_string(), identity.clone());
        Ok(())
    }

    fn load_identity(&self, fingerprint: &Fingerprint) -> Result<Option<Identity>> {
        Ok(self.identities.get(&fingerprint.to_string()).cloned())
    }

    fn delete_identity(&mut self, fingerprint: &Fingerprint) -> Result<()> {
        self.identities.remove(&fingerprint.to_string());
        self.private_keys.remove(&fingerprint.to_string());
        Ok(())
    }

    fn store_encrypted_private_key(
        &mut self,
        fingerprint: &Fingerprint,
        encrypted_key: &[u8],
    ) -> Result<()> {
        self.private_keys
            .insert(fingerprint.to_string(), encrypted_key.to_vec());
        Ok(())
    }

    fn load_encrypted_private_key(
        &self,
        fingerprint: &Fingerprint,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .private_keys
            .get(&fingerprint.to_string())
            .map(|k| Zeroizing::new(k.clone())))
    }

    fn list_fingerprints(&self) -> Result<Vec<Fingerprint>> {
        Ok(self
            .identities
            .keys()
            .filter_map(|k| Fingerprint::new(k).ok())
            .collect())
    }
}

#[test]
fn test_create_and_find_account() {
    let mut backend = MockBackend::new();
    let user = UserID::new("Alice", "alice@example.com").unwrap();
    let account =
        AccountEngine::create_account(&mut backend, user, "strongpassword", None).unwrap();

    let found = AccountEngine::find_by_email(&backend, "alice@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(found.fingerprint, account.fingerprint);
}

#[test]
fn test_encrypt_decrypt_for_account() {
    let mut backend = MockBackend::new();
    let user = UserID::new("Bob", "bob@example.com").unwrap();
    let account = AccountEngine::create_account(&mut backend, user, "bobpass123", None).unwrap();

    let plaintext = b"secret message";
    let encrypted =
        AccountEngine::encrypt_for_account(&backend, &account.fingerprint, plaintext).unwrap();
    let decrypted = AccountEngine::decrypt_for_account(
        &backend,
        &account.fingerprint,
        "bobpass123",
        &encrypted,
    )
    .unwrap();
    assert_eq!(*decrypted, plaintext);
}

#[test]
fn test_change_passphrase() {
    let mut backend = MockBackend::new();
    let user = UserID::new("Carol", "carol@example.com").unwrap();
    let account = AccountEngine::create_account(&mut backend, user, "oldpassword", None).unwrap();

    AccountEngine::change_passphrase(
        &mut backend,
        &account.fingerprint,
        "oldpassword",
        "newpassword",
    )
    .unwrap();

    let encrypted =
        AccountEngine::encrypt_for_account(&backend, &account.fingerprint, b"test").unwrap();
    let decrypted = AccountEngine::decrypt_for_account(
        &backend,
        &account.fingerprint,
        "newpassword",
        &encrypted,
    )
    .unwrap();
    assert_eq!(*decrypted, b"test");
}

#[test]
fn test_delete_account() {
    let mut backend = MockBackend::new();
    let user = UserID::new("Dave", "dave@example.com").unwrap();
    let account = AccountEngine::create_account(&mut backend, user, "pass12345", None).unwrap();

    AccountEngine::delete_account(&mut backend, &account.fingerprint).unwrap();
    assert!(
        AccountEngine::find_by_email(&backend, "dave@example.com")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_list_accounts() {
    let mut backend = MockBackend::new();
    let u1 = UserID::new("Alice", "a@example.com").unwrap();
    let u2 = UserID::new("Bob", "b@example.com").unwrap();
    AccountEngine::create_account(&mut backend, u1, "password1", None).unwrap();
    AccountEngine::create_account(&mut backend, u2, "password2", None).unwrap();

    let list = AccountEngine::list_accounts(&backend).unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn test_export_import_account() {
    let mut backend = MockBackend::new();
    let user = UserID::new("Eve", "eve@example.com").unwrap();
    let account = AccountEngine::create_account(&mut backend, user, "exportpass", None).unwrap();

    let exported =
        AccountEngine::export_account(&backend, &account.fingerprint, "exportpass").unwrap();

    let mut backend2 = MockBackend::new();
    let imported = AccountEngine::import_account(&mut backend2, &exported, "exportpass").unwrap();
    assert_eq!(imported.fingerprint, account.fingerprint);
    assert_eq!(imported.user_id, account.user_id);
}
