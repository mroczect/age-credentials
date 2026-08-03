use age_credentials::core::crypto::*;
use age_credentials::handler::error::AgeCredentialsError;

#[test]
fn test_keygen_success() {
    let kp = generate_keypair().expect("keygen failed");
    assert!(!kp.public_key.is_empty());
    assert!(!kp.secret_key.is_empty());
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let kp = generate_keypair().unwrap();
    let plaintext = b"Hello, Age!";
    let ciphertext = encrypt(plaintext, &kp.public_key).unwrap();
    let decrypted = decrypt(&ciphertext, &kp.secret_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_empty_public_key() {
    let err = encrypt(b"data", "").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("empty"));
        }
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_encrypt_invalid_public_key() {
    let err = encrypt(b"data", "not-a-valid-key").unwrap_err();
    match err {
        AgeCredentialsError::EncryptionFailed {
            code, recipients, ..
        } => {
            assert!(code.contains("INVALID") || code.contains("FAILED"));
            assert_eq!(recipients, vec!["not-a-valid-key"]);
        }
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_decrypt_empty_secret_key() {
    let err = decrypt(b"dummy", "").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("empty"));
        }
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_decrypt_wrong_key() {
    let kp1 = generate_keypair().unwrap();
    let kp2 = generate_keypair().unwrap();
    let ciphertext = encrypt(b"secret", &kp1.public_key).unwrap();
    let err = decrypt(&ciphertext, &kp2.secret_key).unwrap_err();
    match err {
        AgeCredentialsError::DecryptionFailed { code, .. } => {
            assert!(code.contains("NO_MATCHING") || code.contains("DECRYPTION"));
        }
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_passphrase_roundtrip() {
    let plaintext = b"passphrase test";
    let ciphertext = encrypt_with_passphrase(plaintext, "strongpassword").unwrap();
    let decrypted = decrypt_with_passphrase(&ciphertext, "strongpassword").unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_passphrase_too_short_encrypt() {
    let err = encrypt_with_passphrase(b"data", "short").unwrap_err();
    match err {
        AgeCredentialsError::PassphraseTooShort { length, min_length } => {
            assert_eq!(length, 5);
            assert_eq!(min_length, 8);
        }
        _ => panic!("Expected PassphraseTooShort"),
    }
}

#[test]
fn test_passphrase_too_short_decrypt() {
    let err = decrypt_with_passphrase(b"data", "short").unwrap_err();
    match err {
        AgeCredentialsError::PassphraseTooShort { .. } => {}
        _ => panic!("Expected PassphraseTooShort"),
    }
}

#[test]
fn test_decrypt_wrong_passphrase() {
    let ciphertext = encrypt_with_passphrase(b"data", "correctpass").unwrap();
    let err = decrypt_with_passphrase(&ciphertext, "wrongpass12").unwrap_err();
    match err {
        AgeCredentialsError::DecryptionFailed { code, .. } => {
            assert!(code.contains("DECRYPTION") || code.contains("FAILED"));
        }
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_encrypt_multiple() {
    let kp1 = generate_keypair().unwrap();
    let kp2 = generate_keypair().unwrap();
    let ciphertext = encrypt_multiple(b"multi", &[&kp1.public_key, &kp2.public_key]).unwrap();
    let dec1 = decrypt(&ciphertext, &kp1.secret_key).unwrap();
    let dec2 = decrypt(&ciphertext, &kp2.secret_key).unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, b"multi");
}

#[test]
fn test_encrypt_multiple_empty_list() {
    let err = encrypt_multiple(b"data", &[]).unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { .. } => {}
        _ => panic!("Expected InvalidData"),
    }
}

#[test]
fn test_encrypt_armored_roundtrip() {
    let kp = generate_keypair().unwrap();
    let plaintext = b"Armored test";
    let armored = encrypt_armored(plaintext, &kp.public_key).unwrap();
    assert!(armored.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
    let decrypted = decrypt(&armored, &kp.secret_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_multiple_armored() {
    let kp1 = generate_keypair().unwrap();
    let kp2 = generate_keypair().unwrap();
    let armored =
        encrypt_multiple_armored(b"multi armored", &[&kp1.public_key, &kp2.public_key]).unwrap();
    assert!(armored.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
    let dec1 = decrypt(&armored, &kp1.secret_key).unwrap();
    assert_eq!(dec1, b"multi armored");
}

#[test]
fn test_armor_empty_public_key() {
    let err = encrypt_armored(b"data", "").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { .. } => {}
        _ => panic!("Expected InvalidData"),
    }
}

#[test]
fn test_read_recipients_from_file_valid() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("recipients.txt");
    std::fs::write(&file_path, "age1...\n# comment\n\nage2...\n").unwrap();
    let recips = read_recipients_from_file(&file_path).unwrap();
    assert_eq!(recips, vec!["age1...", "age2..."]);
}

#[test]
fn test_read_recipients_from_file_invalid_key() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("bad.txt");
    std::fs::write(&file_path, "not-an-age-key").unwrap();
    let err = read_recipients_from_file(&file_path).unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("not-an-age-key"));
        }
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_read_recipients_from_file_empty() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("empty.txt");
    std::fs::write(&file_path, "# only comment\n").unwrap();
    let err = read_recipients_from_file(&file_path).unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("No valid recipient"));
        }
        _ => panic!("Wrong error variant"),
    }
}
