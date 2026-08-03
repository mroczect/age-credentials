use age_credentials::*;

#[test]
fn test_fingerprint_valid_hex() {
    let fp = Fingerprint::new("abcdef0123456789").unwrap();
    assert_eq!(format!("{}", fp), "abcdef0123456789");
}

#[test]
fn test_fingerprint_invalid_non_hex() {
    assert!(Fingerprint::new("not-hex!").is_err());
}

#[test]
fn test_fingerprint_invalid_empty() {
    assert!(Fingerprint::new("").is_err());
}

#[test]
fn test_fingerprint_equality() {
    let a = Fingerprint::new("a").unwrap();
    let b = Fingerprint::new("a").unwrap();
    let c = Fingerprint::new("b").unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_fingerprint_serde() {
    let fp = Fingerprint::new("abcd1234").unwrap();
    let json = serde_json::to_string(&fp).unwrap();
    let fp2: Fingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, fp2);
}

#[test]
fn test_user_id_trims_whitespace() {
    let uid = UserID::new("  Alice  ", "  alice@example.com  ").unwrap();
    assert_eq!(uid.name, "Alice");
    assert_eq!(uid.email, "alice@example.com");
}

#[test]
fn test_validate_user_name_valid() {
    assert!(validate_user_name("Alice").is_ok());
    assert!(validate_user_name("Bob O'Connor").is_ok());
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
