# age-credentials

Identity and credential management built on the age encryption ecosystem.

This crate is a Rust library that brings GnuPG-like identity management -- user IDs, keyrings, passphrase protection, and structured metadata -- to the simplicity of the age encryption format. It is designed for developers who want programmatic control over identities and credentials without depending on a CLI tool or the GnuPG runtime.

**Status:** Active development. Not yet ready for production use. The public API may change before version 1.0.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Dependencies](#dependencies)
- [Quick Start](#quick-start)
- [Cryptography](#cryptography)
  - [Key Generation](#key-generation)
  - [Encryption](#encryption)
  - [Decryption](#decryption)
  - [Multi-Recipient Encryption](#multi-recipient-encryption)
  - [Armored Encryption](#armored-encryption)
  - [Passphrase Encryption](#passphrase-encryption)
  - [Recipient Files](#recipient-files)
- [Type System](#type-system)
  - [Fingerprint](#fingerprint)
  - [UserID](#userid)
  - [Identity](#identity)
  - [Metadata](#metadata)
  - [KeyGenData](#keygendata)
- [Error Handling](#error-handling)
  - [Error Variants](#error-variants)
  - [Result Type Alias](#result-type-alias)
  - [Pattern Matching Errors](#pattern-matching-errors)
- [Module Reference](#module-reference)
- [Testing](#testing)
- [Placeholder Modules](#placeholder-modules)
- [Security Considerations](#security-considerations)
- [Roadmap](#roadmap)
- [License](#license)

## Overview

age-credentials sits on top of [librage](https://github.com/mroczect/librage), which is a safe Rust wrapper around the [rage](https://str4d.dev/rage) implementation of the [age](https://age-encryption.org) encryption specification. While age and rage provide excellent file-level encryption through their command-line interfaces, they do not offer a built-in concept of identity management, keyrings, or user metadata. age-credentials fills that gap by providing:

- Strongly-typed identity primitives (fingerprint, user ID, identity record, metadata).
- Cryptographic operations (key generation, encryption, decryption) with comprehensive error reporting.
- Passphrase-based encryption with a minimum length policy.
- Multi-recipient encryption for sharing secrets across a team.
- Armored output for embedding ciphertext in text-based protocols.
- Recipient file parsing for reading `.age-recipients` style files.
- A zeroized secret key type that overwrites its memory on drop.

This crate does not ship a binary. It is intended to be consumed as a library by applications, CLIs, or other crates that need age-based credential management.

## Architecture

The crate is organized into three top-level modules, each with sub-modules:

```
src/
  config/         Configuration loading and path resolution
    loader/         (placeholder)
    path/           (placeholder)
  core/           Core business logic
    api/            Public-facing identity and key management API (placeholder)
    crypto/         Cryptographic operations (implemented)
    output/         Output formatting in ASCII, JSON, TOML (placeholder)
  handler/        Shared infrastructure
    error/          The AgeCredentialsError enum and Result alias
    types/          Core data types (Fingerprint, UserID, Identity, Metadata, KeyGenData)
  lib.rs          Crate root, re-exports all public modules
```

The `handler` module is consumed by `core` and `config`. The `core::crypto` module is the only fully implemented sub-tree in this release. All other leaf modules are placeholders.

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
age-credentials = "0.1"
```

If you want to use the git repository directly:

```toml
[dependencies]
age-credentials = { git = "https://github.com/mroczect/age-credentials.git" }
```

The crate edition is 2024 and requires a recent nightly or stable Rust toolchain that supports that edition.

## Dependencies

age-credentials depends on the following crates at runtime:

| Crate              | Version | Role                                                           |
| ------------------ | ------- | -------------------------------------------------------------- |
| librage            | git     | Delegates all age encrypt/decrypt/keygen calls to this backend |
| thiserror          | 2.0     | Provides the Error derive macro for AgeCredentialsError        |
| serde              | 1       | Serialization framework for types and metadata                 |
| serde_json         | 1       | JSON serialization for metadata persistence                    |
| zeroize            | 1       | Secure zeroing of secret key memory on drop                    |
| dirs               | 6       | Resolves platform-specific config and data directories         |
| sha2               | 0.11    | SHA-2 hashing for fingerprint computation                      |
| eyre               | 0.6.12  | Ergonomic error reporting                                      |
| color-eyre         | 0.6.5   | Colored terminal error reports                                 |
| tracing            | 0.1.44  | Structured log emission                                        |
| tracing-subscriber | 0.3.23  | Configures the tracing subscriber                              |

The development dependency `tempfile` (3.27.0) is used only in tests for creating temporary recipient files.

## Quick Start

```rust
use age_credentials::core::crypto::*;

// Generate a key pair
let keypair = generate_keypair().expect("key generation failed");

// Encrypt a message to the public key
let plaintext = b"Hello, age-credentials!";
let ciphertext = encrypt(plaintext, &keypair.public_key).expect("encryption failed");

// Decrypt with the secret key
let decrypted = decrypt(&ciphertext, &keypair.secret_key).expect("decryption failed");
assert_eq!(decrypted, plaintext);
```

## Cryptography

All cryptographic functions live under `age_credentials::core::crypto`. The module re-exports every public function from its sub-modules, so you can import them directly:

```rust
use age_credentials::core::crypto::{
    generate_keypair,
    encrypt, decrypt,
    encrypt_multiple,
    encrypt_armored, encrypt_multiple_armored,
    encrypt_with_passphrase, decrypt_with_passphrase,
    read_recipients_from_file,
};
```

### Key Generation

```rust
pub fn generate_keypair() -> Result<KeyGenData>
```

Generates a new age key pair by calling `librage::generate_keypair`. The returned `KeyGenData` contains:

- `public_key: String` -- The age public key string, starting with `age1`.
- `secret_key: Zeroizing<String>` -- The age secret key string, wrapped in `Zeroizing` so that the underlying memory is overwritten with zeroes when the value is dropped.

If librage reports failure, the function returns `Err(AgeCredentialsError::KeyGenFailed)`. If librage reports success but provides no data, the same error variant is returned with a message indicating the absence of data.

### Encryption

```rust
pub fn encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>>
pub fn encrypt_multiple(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>>
```

`encrypt` encrypts the given plaintext bytes to a single public key. It validates that the public key is non-empty before calling librage. If the public key is empty, it returns `Err(AgeCredentialsError::InvalidData)` with the context `"encrypt"` and details `"public key is empty"`.

`encrypt_multiple` encrypts the given plaintext bytes to one or more public keys. It validates that the `public_keys` slice is non-empty. If the slice is empty, it returns `Err(AgeCredentialsError::InvalidData)` with the context `"encrypt multiple"` and details `"at least one public key required"`.

On librage failure, both functions return `Err(AgeCredentialsError::EncryptionFailed)` containing the list of recipients, the error code, and the error message from librage.

On librage success with no data, both functions return `Err(AgeCredentialsError::EncryptionFailed)` with code `"UNKNOWN"` and message `"librage returned success but no data"`.

On success, the ciphertext is returned as a `Vec<u8>`.

### Decryption

```rust
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>>
```

Decrypts the given ciphertext using the provided secret key. The function validates that the secret key is non-empty. If the secret key is empty, it returns `Err(AgeCredentialsError::InvalidData)` with the context `"decrypt"` and details `"secret key is empty"`.

This function handles both binary and armored ciphertext transparently because librage detects the format automatically.

On librage failure, the function returns `Err(AgeCredentialsError::DecryptionFailed)` with `identity: None`, a hint suggesting the user verify the secret key or ciphertext integrity, and the error code and message from librage.

On success, the plaintext is returned as a `Vec<u8>`.

### Multi-Recipient Encryption

Multi-recipient encryption produces a single ciphertext that can be decrypted by any one of the corresponding secret keys. This is useful for sharing a secret with a group without creating separate ciphertexts for each member.

```rust
let kp1 = generate_keypair().unwrap();
let kp2 = generate_keypair().unwrap();

let ciphertext = encrypt_multiple(b"shared secret", &[&kp1.public_key, &kp2.public_key]).unwrap();

// Either secret key can decrypt
let dec1 = decrypt(&ciphertext, &kp1.secret_key).unwrap();
let dec2 = decrypt(&ciphertext, &kp2.secret_key).unwrap();
assert_eq!(dec1, dec2);
```

### Armored Encryption

```rust
pub fn encrypt_armored(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>>
pub fn encrypt_multiple_armored(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>>
```

These functions behave identically to `encrypt` and `encrypt_multiple` except that the output is ASCII-armored. The returned bytes begin with the header `-----BEGIN AGE ENCRYPTED FILE-----`. Armored output is suitable for embedding in email, JSON fields, environment variables, or any text-based transport.

Armored ciphertext can be decrypted using the same `decrypt` function. librage detects the armored format and handles it transparently.

### Passphrase Encryption

```rust
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>>
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>>
```

These functions encrypt and decrypt using a passphrase instead of a public/secret key pair. They are subject to a minimum passphrase length of 8 characters, enforced before any call to librage.

If the passphrase is shorter than 8 characters, the function returns `Err(AgeCredentialsError::PassphraseTooShort)` containing the provided length and the minimum length.

Example:

```rust
let ciphertext = encrypt_with_passphrase(b"sensitive data", "a-strong-passphrase").unwrap();
let plaintext = decrypt_with_passphrase(&ciphertext, "a-strong-passphrase").unwrap();
assert_eq!(plaintext, b"sensitive data");
```

### Recipient Files

```rust
pub fn read_recipients_from_file(path: impl AsRef<Path>) -> Result<Vec<String>>
```

Reads a recipient list from a text file. The file format follows the convention used by age:

- Each line is treated as a recipient public key.
- Lines starting with `#` are comments and are skipped.
- Blank lines (or lines that are only whitespace) are skipped.
- Every non-comment, non-blank line must start with the string `age`. If a line does not, the function returns `Err(AgeCredentialsError::InvalidData)` with the context `"recipient file"` and details indicating the line number and the offending content.
- If no valid recipients are found in the file, the function returns `Err(AgeCredentialsError::InvalidData)` with details `"No valid recipient found in file"`.
- I/O errors when opening or reading the file are returned as `Err(AgeCredentialsError::Io)` with the file path and the underlying std::io::Error.

Example recipient file:

```
# Team members
age1qyqszqgp7y9y9l9w9rw9r6jg2w3q4szqgp7y9y9l9w9rw9r6jg2w3q4szqgp
age1abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678
```

## Type System

All types live under `age_credentials::handler::types` and are re-exported at the crate root.

### Fingerprint

```rust
pub struct Fingerprint(String);
```

A validated hexadecimal string used to uniquely identify an age key pair. Construction is performed through the `new` method, which rejects:

- Empty strings.
- Strings containing characters that are not ASCII hex digits (0-9, a-f, A-F).

The type implements `Debug`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`, and `Display` (where Display yields the inner hex string).

```rust
use age_credentials::Fingerprint;

let fp = Fingerprint::new("a1b2c3d4e5f6").unwrap();
assert_eq!(fp.to_string(), "a1b2c3d4e5f6");

Fingerprint::new("").unwrap_err();           // empty
Fingerprint::new("not-hex!").unwrap_err();   // non-hex character
```

### UserID

```rust
pub struct UserID {
    pub name: String,
    pub email: String,
}
```

A validated user identity consisting of a name and an email address. Construction is performed through the `new` method, which rejects:

- Names that are empty or contain only whitespace.
- Emails that do not contain the `@` character.

The `to_formatted` method returns the string `Name <email>`.

The type implements `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, and `Deserialize`.

```rust
use age_credentials::UserID;

let uid = UserID::new("Alice Smith", "alice@example.com").unwrap();
assert_eq!(uid.to_formatted(), "Alice Smith <alice@example.com>");

UserID::new("", "a@b.com").unwrap_err();       // empty name
UserID::new("Bob", "no-at-sign").unwrap_err();  // missing @
```

### Identity

```rust
pub struct Identity {
    pub fingerprint: Fingerprint,
    pub user_id: UserID,
    pub label: Option<String>,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub created_at: i64,
}
```

A full identity record. Fields:

- `fingerprint` -- The unique hex fingerprint of this identity.
- `user_id` -- The name and email of the identity holder.
- `label` -- An optional human-readable label for organizational purposes (for example, "work" or "personal").
- `private_key_path` -- The filesystem path where the secret key file is stored.
- `public_key_path` -- The filesystem path where the public key file is stored.
- `created_at` -- Unix timestamp of when the identity was created.

This struct does not perform validation on construction. Validation is delegated to `Fingerprint::new` and `UserID::new` when building the constituent fields.

The type implements `Debug`, `Clone`, `Serialize`, and `Deserialize`.

### Metadata

```rust
pub struct Metadata {
    pub identities: Vec<Identity>,
    pub default_identity: Option<Fingerprint>,
}
```

The top-level metadata structure for a keyring. Fields:

- `identities` -- The list of all identities managed by this keyring.
- `default_identity` -- The fingerprint of the identity that should be used when no explicit identity is specified. This may be `None`.

Implements `Default` (empty identity list, no default), `Debug`, `Clone`, `Serialize`, and `Deserialize`.

```rust
use age_credentials::{Metadata, Identity, Fingerprint, UserID};

let mut meta = Metadata::default();
let ident = Identity {
    fingerprint: Fingerprint::new("abc123").unwrap(),
    user_id: UserID::new("Alice", "alice@example.com").unwrap(),
    label: Some("work".into()),
    private_key_path: "/home/user/.age/keys/abc123.age".into(),
    public_key_path: "/home/user/.age/keys/abc123.pub".into(),
    created_at: 1700000000,
};
meta.identities.push(ident);
meta.default_identity = Some(Fingerprint::new("abc123").unwrap());
```

### KeyGenData

```rust
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
```

The return type of `generate_keypair`. The `secret_key` field is wrapped in `Zeroizing<String>` from the `zeroize` crate. When the `KeyGenData` value is dropped, the secret key string is overwritten with zeroes in memory before deallocation. This reduces the window during which the secret key material is exposed in RAM.

The `Zeroizing` wrapper also supports serialization through the `serde` feature of the `zeroize` crate, which is enabled in this project's Cargo.toml.

## Error Handling

All fallible operations in age-credentials return `handler::error::Result<T>`, which is an alias for `std::result::Result<T, AgeCredentialsError>`.

### Error Variants

The `AgeCredentialsError` enum is defined with `thiserror` and implements `std::error::Error`, `Debug`, and `Display`. Each variant produces a human-readable error message through the `#[error(...)]` attribute.

| Variant               | Fields                                                                        | Display format                                                                   |
| --------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `Io`                  | `path: PathBuf`, `source: std::io::Error`                                     | "I/O error at {path}: {source}"                                                  |
| `Serialization`       | `target: &'static str`, `path: PathBuf`, `source: serde_json::Error`          | "Serialization error for {target} at {path}: {source}"                           |
| `DuplicateIdentity`   | `fingerprint: String`, `keyring_path: PathBuf`                                | "Duplicate identity {fingerprint} in keyring at {keyring_path}"                  |
| `IdentityNotFound`    | `search_key: String`, `keyring_path: PathBuf`                                 | "Identity not found: {search_key} in keyring at {keyring_path}"                  |
| `InvalidEmail`        | `email: String`                                                               | "Invalid email address: {email}"                                                 |
| `InvalidName`         | `name: String`                                                                | "Invalid name: {name}"                                                           |
| `PassphraseIncorrect` | `identity: String`                                                            | "Passphrase incorrect for identity {identity}"                                   |
| `EncryptionFailed`    | `recipients: Vec<String>`, `code: String`, `message: String`                  | "Encryption failed for recipients {recipients:?}: [{code}] {message}"            |
| `DecryptionFailed`    | `identity: Option<String>`, `hint: String`, `code: String`, `message: String` | "Decryption failed for identity {identity:?} (hint: {hint}): [{code}] {message}" |
| `KeyGenFailed`        | `reason: String`                                                              | "Key generation failed: {reason}"                                                |
| `MetadataNotFound`    | `path: PathBuf`                                                               | "Metadata file not found at {path}"                                              |
| `InvalidData`         | `context: &'static str`, `details: String`                                    | "Invalid data in {context}: {details}"                                           |
| `Config`              | `message: String`, `location: String`                                         | "Configuration error: {message} (at {location})"                                 |
| `PassphraseTooShort`  | `length: usize`, `min_length: usize`                                          | "Passphrase too short: {length} chars, minimum {min_length}"                     |
| `InvalidFingerprint`  | `reason: String`                                                              | "Invalid fingerprint: {reason}"                                                  |
| `InvalidUserId`       | `reason: String`                                                              | "Invalid User ID: {reason}"                                                      |

### Result Type Alias

```rust
pub type Result<T> = std::result::Result<T, AgeCredentialsError>;
```

This alias is exported at the crate root. Use it in your own functions that propagate age-credentials errors:

```rust
use age_credentials::Result;

fn my_operation() -> Result<String> {
    let kp = age_credentials::core::crypto::generate_keypair()?;
    Ok(kp.public_key)
}
```

### Pattern Matching Errors

Because `AgeCredentialsError` is an enum, you can match on specific variants to implement conditional logic or user-facing messaging:

```rust
use age_credentials::core::crypto::*;
use age_credentials::handler::error::AgeCredentialsError;

match encrypt(b"data", "") {
    Ok(_) => println!("Encrypted successfully"),
    Err(AgeCredentialsError::InvalidData { context, details }) => {
        eprintln!("Validation error in {}: {}", context, details);
    }
    Err(AgeCredentialsError::EncryptionFailed { recipients, code, message }) => {
        eprintln!("Encryption failed for {:?}: [{}] {}", recipients, code, message);
    }
    Err(e) => eprintln!("Unexpected error: {}", e),
}
```

## Module Reference

| Module path      | Status      | Description                                                                                                                    |
| ---------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `config`         | Partial     | Top-level configuration module. Declares `loader` and `path` sub-modules.                                                      |
| `config::loader` | Placeholder | Configuration file loading. No public API yet.                                                                                 |
| `config::path`   | Placeholder | Path resolution for configuration and keyring directories. No public API yet.                                                  |
| `core`           | Partial     | Top-level core module. Declares `api`, `crypto`, and `output` sub-modules.                                                     |
| `core::api`      | Placeholder | Identity and key management API. Declares `private_keys`, `public_keys`, `user_email`, `user_name`. None have implementations. |
| `core::crypto`   | Implemented | All cryptographic operations. Re-exports `armor`, `decrypt`, `encrypt`, `keygen`, `passphrase`, `recipient`.                   |
| `core::output`   | Placeholder | Output formatting. Declares `ascii`, `json`, `toml`. None have implementations.                                                |
| `handler`        | Implemented | Shared infrastructure. Declares `error` and `types`.                                                                           |
| `handler::error` | Implemented | The `AgeCredentialsError` enum and `Result` alias.                                                                             |
| `handler::types` | Implemented | Core data types: `Fingerprint`, `UserID`, `Identity`, `Metadata`, `KeyGenData`.                                                |

The crate root (`lib.rs`) declares `config`, `core`, and `handler` as public modules and re-exports all their contents with `pub use`. This means you can access types and functions from the crate root or through their full module path:

```rust
// Both are equivalent
use age_credentials::Fingerprint;
use age_credentials::handler::types::Fingerprint;
```

## Testing

The test suite contains 47 tests across three files:

**crypto_tests (17 tests)**

| Test name                                    | What it verifies                                                                                 |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `test_keygen_success`                        | generate_keypair returns non-empty public and secret keys                                        |
| `test_encrypt_decrypt_roundtrip`             | encrypt followed by decrypt recovers the original plaintext                                      |
| `test_encrypt_empty_public_key`              | encrypt rejects an empty public key with InvalidData                                             |
| `test_encrypt_invalid_public_key`            | encrypt rejects a malformed public key with EncryptionFailed                                     |
| `test_decrypt_empty_secret_key`              | decrypt rejects an empty secret key with InvalidData                                             |
| `test_decrypt_wrong_key`                     | decrypt with the wrong secret key returns DecryptionFailed                                       |
| `test_passphrase_roundtrip`                  | encrypt_with_passphrase followed by decrypt_with_passphrase recovers the original plaintext      |
| `test_passphrase_too_short_encrypt`          | encrypt_with_passphrase rejects a short passphrase with PassphraseTooShort                       |
| `test_passphrase_too_short_decrypt`          | decrypt_with_passphrase rejects a short passphrase with PassphraseTooShort                       |
| `test_decrypt_wrong_passphrase`              | decrypt_with_passphrase with the wrong passphrase returns DecryptionFailed                       |
| `test_encrypt_multiple`                      | encrypt_multiple produces ciphertext decryptable by any recipient secret key                     |
| `test_encrypt_multiple_empty_list`           | encrypt_multiple rejects an empty recipient list with InvalidData                                |
| `test_encrypt_armored_roundtrip`             | encrypt_armored produces output starting with the age header, and decrypt recovers the plaintext |
| `test_encrypt_multiple_armored`              | encrypt_multiple_armored produces armored output decryptable by any recipient                    |
| `test_armor_empty_public_key`                | encrypt_armored rejects an empty public key with InvalidData                                     |
| `test_read_recipients_from_file_valid`       | reads a file with keys, comments, and blank lines, returning the two valid keys                  |
| `test_read_recipients_from_file_invalid_key` | rejects a line that does not start with "age"                                                    |
| `test_read_recipients_from_file_empty`       | rejects a file with only comments, returning InvalidData about no valid recipient                |

**error_tests (16 tests)**

Every test constructs an error variant, formats it with Display, and asserts that the formatted string contains the relevant field values. These tests also verify the Debug output richness and the Result type alias behavior.

**types_tests (14 tests)**

Every test constructs, validates, serializes, and deserializes the core types (Fingerprint, UserID, Identity, Metadata). Negative tests verify that invalid inputs are rejected.

Run the test suite:

```bash
cargo test
```

## Placeholder Modules

The following modules are declared and compile successfully but contain no implementation. They exist to establish the public module tree and will be populated in future releases.

- **config::loader** -- Will handle loading configuration files from disk, including keyring location, default identity selection, and policy settings.
- **config::path** -- Will resolve platform-specific paths for the configuration directory, keyring directory, and metadata file using the `dirs` crate.
- **core::api::private_keys** -- Will expose functions for listing, retrieving, and deleting private keys from the keyring.
- **core::api::public_keys** -- Will expose functions for listing and retrieving public keys, including import and export.
- **core::api::user_email** -- Will expose functions for managing email addresses associated with identities.
- **core::api::user_name** -- Will expose functions for managing names associated with identities.
- **core::output::ascii** -- Will format keyring and identity information as human-readable ASCII text.
- **core::output::json** -- Will format keyring and identity information as structured JSON.
- **core::output::toml** -- Will format keyring and identity information as TOML, suitable for configuration files.

## Security Considerations

- **Secret key zeroization.** The `KeyGenData::secret_key` field is wrapped in `Zeroizing<String>`. When the `KeyGenData` value goes out of scope, the secret key memory is overwritten with zeroes. However, this only protects against reads of deallocated memory. While the value is live, the secret key exists in plain text on the heap. Applications should minimize the lifetime of `KeyGenData` values and avoid cloning the secret key.
- **Passphrase minimum length.** The library enforces a minimum passphrase length of 8 characters before calling librage. This is a defense against trivially weak passphrases but is not a substitute for proper passphrase strength validation or key derivation best practices.
- **No constant-time operations.** age-credentials does not perform constant-time comparison on fingerprints, user IDs, or ciphertext. This is acceptable because these values are not secrets in the cryptographic sense (fingerprints are public identifiers, and ciphertext is intended to be transmitted). However, applications should not use this library's comparison logic for secret values such as passphrases.
- **Underlying backend.** All cryptographic security depends on the correctness and soundness of librage and the rage implementation. age-credentials is a wrapper and does not implement any cryptographic primitives itself.
- **Email validation is minimal.** The `UserID::new` function only checks that the email contains the `@` character. It does not validate RFC 5322 compliance, domain existence, or MX records. Applications that require stronger email validation should layer their own validation on top.

## Roadmap

The following capabilities are planned for future releases. This list is not binding and may change.

- Configuration file loading and path resolution (config::loader, config::path).
- Identity and key management API (core::api sub-modules).
- Keyring operations: add identity, remove identity, set default identity, list identities.
- Output formatters: ASCII, JSON, TOML (core::output sub-modules).
- Metadata persistence: load and save the Metadata struct to disk as JSON or TOML.
- Configurable passphrase policies (minimum length, complexity rules).
- SSH key recipient support.
- Identity file encryption and decryption (encrypting the metadata or keyring itself with a master key).
- Integration tests that exercise full workflows (create identity, encrypt, decrypt, rotate).
- Documentation and examples directory.

## License

This project is licensed under the MIT License. See the LICENSE file in the repository for the full text.
