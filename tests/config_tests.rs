use age_credentials::{AgeCredentialsError, ConfigLoader, KeyringPath, Metadata};
use tempfile::TempDir;

#[test]
fn test_keyring_new_creates_directory() {
    let dir = TempDir::new().unwrap();
    let kp = KeyringPath::new(dir.path()).unwrap();
    assert!(kp.private_dir().exists());
    assert!(kp.public_dir().exists());
}

#[test]
fn test_keyring_open_existing_fails_for_missing() {
    let nonexistent = std::env::temp_dir().join("nonexistent-keyring");
    let err = KeyringPath::open_existing(&nonexistent).unwrap_err();
    assert!(format!("{}", err).contains("not found"));
}

#[test]
fn test_keyring_new_empty_path() {
    let err = KeyringPath::new("").unwrap_err();
    assert!(format!("{}", err).contains("empty"));
}

#[test]
fn test_save_and_load_metadata() {
    let dir = TempDir::new().unwrap();
    let kp = KeyringPath::new(dir.path()).unwrap();
    let meta = Metadata::default();
    ConfigLoader::save(kp.metadata_file(), &meta).unwrap();
    let loaded = ConfigLoader::load(kp.metadata_file()).unwrap();
    assert!(loaded.identities.is_empty());
}

#[test]
fn test_load_missing_file() {
    let dir = TempDir::new().unwrap();
    let kp = KeyringPath::new(dir.path()).unwrap();
    let err = ConfigLoader::load(kp.metadata_file()).unwrap_err();
    match err {
        AgeCredentialsError::Io { .. } => {}
        _ => panic!("Expected Io error"),
    }
}

#[test]
fn test_fingerprint_paths() {
    let dir = TempDir::new().unwrap();
    let kp = KeyringPath::new(dir.path()).unwrap();
    let priv_path = kp.fingerprint_private_path("abc123");
    let pub_path = kp.fingerprint_public_path("abc123");
    assert!(priv_path.ends_with("abc123.age"));
    assert!(pub_path.ends_with("abc123.pub"));
}
