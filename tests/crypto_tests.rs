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
    let ciphertext = encrypt_with_passphrase(plaintext, "s3cret").unwrap();
    let decrypted = decrypt_with_passphrase(&ciphertext, "s3cret").unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_wrong_passphrase() {
    let ciphertext = encrypt_with_passphrase(b"data", "correct").unwrap();
    let err = decrypt_with_passphrase(&ciphertext, "wrong").unwrap_err();
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
