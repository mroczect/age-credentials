use age_credentials::AgeCredentialsError;
use age_credentials::api::*;
use age_credentials::core::crypto::generate_keypair;
use tempfile::TempDir;

#[test]
fn test_validate_user_name_valid() {
    assert!(validate_user_name("Alice").is_ok());
    assert!(validate_user_name("Bob O'Connor").is_ok());
    assert!(validate_user_name("Jean-Luc").is_ok());
}

#[test]
fn test_validate_user_name_empty() {
    let err = validate_user_name("").unwrap_err();
    assert!(format!("{}", err).contains("empty"));
}

#[test]
fn test_validate_user_name_too_short() {
    let err = validate_user_name("A").unwrap_err();
    assert!(format!("{}", err).contains("too short"));
}

#[test]
fn test_validate_user_name_invalid_char() {
    let err = validate_user_name("Alice!").unwrap_err();
    assert!(format!("{}", err).contains("Invalid character"));
}

#[test]
fn test_validate_user_email_valid() {
    assert!(validate_user_email("alice@example.com").is_ok());
    assert!(validate_user_email("a.b+c@d-e.net").is_ok());
}

#[test]
fn test_validate_user_email_empty() {
    let err = validate_user_email("").unwrap_err();
    assert!(format!("{}", err).contains("empty"));
}

#[test]
fn test_validate_user_email_no_at() {
    let err = validate_user_email("no-at-sign").unwrap_err();
    assert!(format!("{}", err).contains("exactly one '@'"));
}

#[test]
fn test_validate_user_email_multiple_at() {
    let err = validate_user_email("a@b@c.com").unwrap_err();
    assert!(format!("{}", err).contains("exactly one '@'"));
}

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
