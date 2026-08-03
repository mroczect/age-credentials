use age_credentials::*;
use std::time::SystemTime;

#[test]
fn test_fingerprint_display() {
    let fp = Fingerprint("sha256:abcdef123456".into());
    assert_eq!(format!("{}", fp), "sha256:abcdef123456");
}

#[test]
fn test_fingerprint_equality() {
    let a = Fingerprint("a".into());
    let b = Fingerprint("a".into());
    let c = Fingerprint("b".into());
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_fingerprint_serde() {
    let fp = Fingerprint("fp1".into());
    let json = serde_json::to_string(&fp).unwrap();
    let fp2: Fingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, fp2);
}

#[test]
fn test_user_id_new_and_formatted() {
    let uid = UserID::new("Alice", "alice@example.com");
    assert_eq!(uid.name, "Alice");
    assert_eq!(uid.email, "alice@example.com");
    assert_eq!(uid.to_formatted(), "Alice <alice@example.com>");
}

#[test]
fn test_user_id_serde() {
    let uid = UserID::new("Bob", "bob@test.org");
    let json = serde_json::to_string(&uid).unwrap();
    let uid2: UserID = serde_json::from_str(&json).unwrap();
    assert_eq!(uid, uid2);
}

#[test]
fn test_identity_struct() {
    let created = SystemTime::now();
    let identity = Identity {
        fingerprint: Fingerprint("fp-xyz".into()),
        user_id: UserID::new("Carol", "carol@dev.io"),
        label: Some("work".into()),
        private_key_path: "private/identity-1.age".into(),
        public_key_path: "public/identity-1.pub".into(),
        created_at: created,
    };
    assert_eq!(identity.fingerprint.0, "fp-xyz");
    assert_eq!(identity.user_id.email, "carol@dev.io");
    assert_eq!(identity.label, Some("work".to_string()));
}

#[test]
fn test_identity_serde() {
    let created = SystemTime::UNIX_EPOCH;
    let identity = Identity {
        fingerprint: Fingerprint("fp-serde".into()),
        user_id: UserID::new("Serde", "serde@test.com"),
        label: None,
        private_key_path: "priv".into(),
        public_key_path: "pub".into(),
        created_at: created,
    };
    let json = serde_json::to_string(&identity).unwrap();
    let ident2: Identity = serde_json::from_str(&json).unwrap();
    assert_eq!(identity.fingerprint, ident2.fingerprint);
    assert_eq!(identity.user_id, ident2.user_id);
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
        fingerprint: Fingerprint("fp-meta".into()),
        user_id: UserID::new("Meta", "meta@test.com"),
        label: None,
        private_key_path: "p1".into(),
        public_key_path: "p1.pub".into(),
        created_at: SystemTime::now(),
    };
    meta.identities.push(ident);
    assert_eq!(meta.identities.len(), 1);
    meta.default_identity = Some(Fingerprint("fp-meta".into()));
    assert!(meta.default_identity.is_some());
}

#[test]
fn test_metadata_serde() {
    let mut meta = Metadata::default();
    let ident = Identity {
        fingerprint: Fingerprint("serde-fp".into()),
        user_id: UserID::new("SerdeMeta", "serde@meta.org"),
        label: Some("test".into()),
        private_key_path: "priv.key".into(),
        public_key_path: "pub.key".into(),
        created_at: SystemTime::UNIX_EPOCH,
    };
    meta.identities.push(ident);
    let json = serde_json::to_string(&meta).unwrap();
    let _meta2: Metadata = serde_json::from_str(&json).unwrap();
}
