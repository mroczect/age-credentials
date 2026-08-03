use age_credentials::AgeCredentialsError;
use age_credentials::api::*;
use age_credentials::core::crypto::generate_keypair;
use tempfile::TempDir;

#[test]
fn test_write_and_read_public_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.pub");
    let kp = generate_keypair().unwrap();
    let key = &kp.public_key;
    write_public_key(&path, key).unwrap();
    let read = read_public_key(&path).unwrap();
    assert_eq!(read, key.to_string());
}

#[test]
fn test_write_public_key_invalid() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad.pub");
    let err = write_public_key(&path, "notage1").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("Invalid age public key"));
        }
        _ => panic!("Wrong error"),
    }
}

#[test]
fn test_read_public_key_empty_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.pub");
    std::fs::write(&path, "").unwrap();
    let err = read_public_key(&path).unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("empty"));
        }
        _ => panic!("Wrong error"),
    }
}

#[test]
fn test_write_and_read_encrypted_private_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.age");
    let data = vec![1, 2, 3, 4, 5];
    write_encrypted_private_key(&path, &data).unwrap();
    let read = read_encrypted_private_key(&path).unwrap();
    assert_eq!(*read, data);
}

#[test]
fn test_write_encrypted_private_key_empty() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.age");
    let err = write_encrypted_private_key(&path, &[]).unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { .. } => {}
        _ => panic!("Wrong error"),
    }
}
