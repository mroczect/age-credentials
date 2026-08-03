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
fn test_user_id_valid() {
    let uid = UserID::new("Alice", "alice@example.com").unwrap();
    assert_eq!(uid.name, "Alice");
    assert_eq!(uid.email, "alice@example.com");
    assert_eq!(uid.to_formatted(), "Alice <alice@example.com>");
}

#[test]
fn test_user_id_empty_name() {
    assert!(UserID::new("", "a@b.com").is_err());
    assert!(UserID::new("   ", "a@b.com").is_err());
}

#[test]
fn test_user_id_invalid_email_no_at() {
    assert!(UserID::new("Bob", "no-at-sign").is_err());
}

#[test]
fn test_user_id_serde() {
    let uid = UserID::new("Bob", "bob@test.org").unwrap();
    let json = serde_json::to_string(&uid).unwrap();
    let uid2: UserID = serde_json::from_str(&json).unwrap();
    assert_eq!(uid, uid2);
}

#[test]
fn test_identity_struct() {
    let identity = Identity {
        fingerprint: Fingerprint::new("abc123").unwrap(),
        user_id: UserID::new("Carol", "carol@dev.io").unwrap(),
        label: Some("work".into()),
        private_key_path: "private/identity-1.age".into(),
        public_key_path: "public/identity-1.pub".into(),
        created_at: 1625097600,
    };
    assert_eq!(format!("{}", identity.fingerprint), "abc123");
    assert_eq!(identity.user_id.email, "carol@dev.io");
    assert_eq!(identity.label, Some("work".to_string()));
    assert_eq!(identity.created_at, 1625097600);
}

#[test]
fn test_identity_serde() {
    let identity = Identity {
        fingerprint: Fingerprint::new("abc123").unwrap(),
        user_id: UserID::new("Serde", "serde@test.com").unwrap(),
        label: None,
        private_key_path: "priv".into(),
        public_key_path: "pub".into(),
        created_at: 1625097600,
    };
    let json = serde_json::to_string(&identity).unwrap();
    let ident2: Identity = serde_json::from_str(&json).unwrap();
    assert_eq!(identity.fingerprint, ident2.fingerprint);
    assert_eq!(identity.user_id, ident2.user_id);
    assert_eq!(identity.created_at, ident2.created_at);
}

#[test]
fn test_metadata_default() {
    let meta = Metadata::default();
    assert!(meta.identities.is_empty());
    assert!(meta.default_identity.is_none());
}

#[test]
fn test_metadata_add_identity() {
    let mut meta = Metadata::default();
    let ident = Identity {
        fingerprint: Fingerprint::new("abcdef").unwrap(),
        user_id: UserID::new("Meta", "meta@test.com").unwrap(),
        label: None,
        private_key_path: "p1".into(),
        public_key_path: "p1.pub".into(),
        created_at: 1625097600,
    };
    meta.identities.push(ident);
    assert_eq!(meta.identities.len(), 1);
    meta.default_identity = Some(Fingerprint::new("abcdef").unwrap());
    assert!(meta.default_identity.is_some());
}

#[test]
fn test_metadata_serde() {
    let mut meta = Metadata::default();
    let ident = Identity {
        fingerprint: Fingerprint::new("abcdef").unwrap(),
        user_id: UserID::new("SerdeMeta", "serde@meta.org").unwrap(),
        label: Some("test".into()),
        private_key_path: "priv.key".into(),
        public_key_path: "pub.key".into(),
        created_at: 1625097600,
    };
    meta.identities.push(ident);
    let json = serde_json::to_string(&meta).unwrap();
    let _meta2: Metadata = serde_json::from_str(&json).unwrap();
}
