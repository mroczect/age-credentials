use age_credentials::AgeCredentialsError;
use age_credentials::output::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestStruct {
    name: String,
    value: i32,
}

#[test]
fn test_hex_encode_decode_roundtrip() {
    let data = vec![0, 255, 128, 99];
    let hex = hex_encode(&data);
    assert_eq!(hex, "00ff8063");
    let decoded = hex_decode(&hex).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_hex_decode_empty() {
    let err = hex_decode("").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { .. } => {}
        _ => panic!("Wrong error"),
    }
}

#[test]
fn test_hex_decode_odd_length() {
    let err = hex_decode("abc").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("odd"));
        }
        _ => panic!("Wrong error"),
    }
}

#[test]
fn test_hex_decode_invalid_char() {
    let err = hex_decode("abz0").unwrap_err();
    match err {
        AgeCredentialsError::InvalidData { details, .. } => {
            assert!(details.contains("Invalid hex character"));
        }
        _ => panic!("Wrong error"),
    }
}

#[test]
fn test_json_roundtrip() {
    let obj = TestStruct {
        name: "Alice".into(),
        value: 42,
    };
    let json = to_json_pretty(&obj).unwrap();
    let obj2: TestStruct = from_json(&json).unwrap();
    assert_eq!(obj, obj2);
}

#[test]
fn test_from_json_invalid() {
    let err = from_json::<TestStruct>("not json").unwrap_err();
    match err {
        AgeCredentialsError::Serialization { .. } => {}
        _ => panic!("Wrong error"),
    }
}

#[test]
fn test_toml_roundtrip() {
    let obj = TestStruct {
        name: "Bob".into(),
        value: -7,
    };
    let toml_str = to_toml_pretty(&obj).unwrap();
    let obj2: TestStruct = from_toml(&toml_str).unwrap();
    assert_eq!(obj, obj2);
}

#[test]
fn test_from_toml_invalid() {
    let err = from_toml::<TestStruct>("not = toml").unwrap_err();
    match err {
        AgeCredentialsError::Serialization { .. } => {}
        _ => panic!("Wrong error"),
    }
}
