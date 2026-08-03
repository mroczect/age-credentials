use age_credentials::AgeCredentialsError;
use std::io;

#[test]
fn test_io_error_display() {
    let source = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let err = AgeCredentialsError::Io {
        path: "/tmp/test.txt".into(),
        source,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("/tmp/test.txt"));
    assert!(msg.contains("file not found"));
}

#[test]
fn test_serialization_error_display() {
    let source: Box<dyn std::error::Error + Send + Sync> =
        Box::new(serde_json::from_str::<serde_json::Value>("invalid").unwrap_err());
    let err = AgeCredentialsError::Serialization {
        target: "metadata",
        path: "/tmp/metadata.json".into(),
        source,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("metadata"));
    assert!(msg.contains("/tmp/metadata.json"));

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
fn test_duplicate_identity_display() {
    let err = AgeCredentialsError::DuplicateIdentity {
        fingerprint: "abc123".into(),
        keyring_path: "/home/user/.age".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("abc123"));
    assert!(msg.contains("/home/user/.age"));
}

#[test]
fn test_identity_not_found_display() {
    let err = AgeCredentialsError::IdentityNotFound {
        search_key: "bob@work.com".into(),
        keyring_path: "/custom/keyring".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("bob@work.com"));
    assert!(msg.contains("/custom/keyring"));
}

#[test]
fn test_invalid_email_display() {
    let err = AgeCredentialsError::InvalidEmail {
        email: "notanemail".into(),
    };
    assert!(format!("{}", err).contains("notanemail"));
}

#[test]
fn test_invalid_name_display() {
    let err = AgeCredentialsError::InvalidName { name: "123".into() };
    assert!(format!("{}", err).contains("123"));
}

#[test]
fn test_passphrase_incorrect_display() {
    let err = AgeCredentialsError::PassphraseIncorrect {
        identity: "key-001".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("key-001"));
    assert!(msg.to_lowercase().contains("passphrase"));
}

#[test]
fn test_encryption_failed_display() {
    let err = AgeCredentialsError::EncryptionFailed {
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
    let err = AgeCredentialsError::DecryptionFailed {
        identity: Some("id1".into()),
        hint: "check passphrase or key file".into(),
        code: "DECRYPTION_FAILED".into(),
        message: "No matching keys".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("id1"));
    assert!(msg.contains("check passphrase or key file"));
    assert!(msg.contains("DECRYPTION_FAILED"));
    assert!(msg.contains("No matching keys"));
}

#[test]
fn test_keygen_failed_display() {
    let err = AgeCredentialsError::KeyGenFailed {
        reason: "insufficient entropy".into(),
    };
    assert!(format!("{}", err).contains("insufficient entropy"));
}

#[test]
fn test_metadata_not_found_display() {
    let err = AgeCredentialsError::MetadataNotFound {
        path: "/root/.age/metadata.json".into(),
    };
    assert!(format!("{}", err).contains("/root/.age/metadata.json"));
}

#[test]
fn test_invalid_data_display() {
    let err = AgeCredentialsError::InvalidData {
        context: "keyring",
        details: "expected public key but found SSH".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("keyring"));
    assert!(msg.contains("expected public key but found SSH"));
}

#[test]
fn test_config_error_display() {
    let err = AgeCredentialsError::Config {
        message: "missing required field".into(),
        location: "keyring.toml line 5".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("missing required field"));
    assert!(msg.contains("keyring.toml line 5"));
}

#[test]
fn test_error_debug_rich() {
    let err = AgeCredentialsError::IdentityNotFound {
        search_key: "test@test.com".into(),
        keyring_path: "/debug/path".into(),
    };
    let debug = format!("{:?}", err);
    assert!(debug.contains("search_key"));
    assert!(debug.contains("test@test.com"));
}

#[test]
fn test_result_type() {
    fn returns_result() -> age_credentials::Result<i32> {
        Ok(42)
    }
    assert_eq!(returns_result().unwrap(), 42);

    fn returns_err() -> age_credentials::Result<i32> {
        Err(AgeCredentialsError::InvalidData {
            context: "test",
            details: "oops".into(),
        })
    }
    assert!(returns_err().is_err());
}

#[test]
fn test_manual_io_conversion() {
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
    let err = AgeCredentialsError::Io {
        path: "/secret".into(),
        source: io_err,
    };
    if let AgeCredentialsError::Io { source, .. } = &err {
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
    } else {
        panic!("Wrong variant");
    }
}

#[test]
fn test_passphrase_too_short_display() {
    let err = AgeCredentialsError::PassphraseTooShort {
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
    let err = AgeCredentialsError::InvalidFingerprint {
        reason: "test reason".into(),
    };
    assert!(format!("{}", err).contains("test reason"));
}

#[test]
fn test_invalid_userid_display() {
    let err = AgeCredentialsError::InvalidUserId {
        reason: "bad user".into(),
    };
    assert!(format!("{}", err).contains("bad user"));
}
