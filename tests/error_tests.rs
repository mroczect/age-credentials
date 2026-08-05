use age_credentials::domain::error::AccountError;
use std::io;

#[test]
fn test_io_error_display() {
    let source = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let err = AccountError::Io { source };
    let msg = format!("{}", err);
    assert!(msg.contains("file not found"));
}

#[test]
fn test_serialization_error_display() {
    let source: Box<dyn std::error::Error + Send + Sync> =
        Box::new(serde_json::from_str::<serde_json::Value>("invalid").unwrap_err());
    let err = AccountError::Serialization { source };
    let msg = format!("{}", err);
    let lower = msg.to_lowercase();
    assert!(
        lower.contains("expected")
            || lower.contains("invalid")
            || lower.contains("key")
            || lower.contains("parse"),
        "Pesan error serialization tidak mengandung indikasi kegagalan parsing: {}",
        msg
    );
}

#[test]
fn test_backend_error_display() {
    let err = AccountError::Backend("something went wrong".into());
    assert!(format!("{}", err).contains("something went wrong"));
}

#[test]
fn test_account_not_found_display() {
    let err = AccountError::AccountNotFound("abc123".into());
    assert!(format!("{}", err).contains("abc123"));
}

#[test]
fn test_duplicate_account_display() {
    let err = AccountError::DuplicateAccount("dup".into());
    assert!(format!("{}", err).contains("dup"));
}

#[test]
fn test_invalid_data_display() {
    let err = AccountError::InvalidData {
        context: "keyring",
        details: "expected public key but found SSH".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("keyring"));
    assert!(msg.contains("expected public key but found SSH"));
}

#[test]
fn test_encryption_failed_display() {
    let err = AccountError::EncryptionFailed {
        recipients: vec!["rec1".into(), "rec2".into()],
        code: "ENCRYPTION_FAILED".into(),
        message: "Missing recipients".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("rec1"));
    assert!(msg.contains("rec2"));
    assert!(msg.contains("ENCRYPTION_FAILED"));
    assert!(msg.contains("Missing recipients"));
}

#[test]
fn test_decryption_failed_display() {
    let err = AccountError::DecryptionFailed {
        hint: "check passphrase or key file".into(),
        code: "DECRYPTION_FAILED".into(),
        message: "No matching keys".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("check passphrase or key file"));
    assert!(msg.contains("DECRYPTION_FAILED"));
    assert!(msg.contains("No matching keys"));
}

#[test]
fn test_keygen_failed_display() {
    let err = AccountError::KeyGenFailed {
        reason: "insufficient entropy".into(),
    };
    assert!(format!("{}", err).contains("insufficient entropy"));
}

#[test]
fn test_passphrase_too_short_display() {
    let err = AccountError::PassphraseTooShort {
        length: 3,
        min_length: 8,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("3"));
    assert!(msg.contains("8"));
    assert!(msg.to_lowercase().contains("too short"));
}

#[test]
fn test_invalid_fingerprint_display() {
    let err = AccountError::InvalidFingerprint {
        reason: "test reason".into(),
    };
    assert!(format!("{}", err).contains("test reason"));
}

#[test]
fn test_invalid_userid_display() {
    let err = AccountError::InvalidUserId {
        reason: "bad user".into(),
    };
    assert!(format!("{}", err).contains("bad user"));
}

#[test]
fn test_result_type() {
    fn returns_result() -> age_credentials::domain::error::Result<i32> {
        Ok(42)
    }
    assert_eq!(returns_result().unwrap(), 42);

    fn returns_err() -> age_credentials::domain::error::Result<i32> {
        Err(AccountError::InvalidData {
            context: "test",
            details: "oops".into(),
        })
    }
    assert!(returns_err().is_err());
}
