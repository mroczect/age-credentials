# age-credentials

**Account management engine built on the age encryption format.**

`age-credentials` is a Rust library that provides a complete, backend‑agnostic account system with identity management, cryptographic operations, and secure key storage on top of the age encryption specification. It is designed for developers who need programmatic control over user accounts and credentials without depending on a CLI tool, a particular storage backend, or a runtime like GnuPG.

This crate is a **library only**. It does not ship a binary.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Dependencies](#dependencies)
- [Quick Start](#quick-start)
- [Account System](#account-system)
  - [AccountBackend Trait](#accountbackend-trait)
  - [AccountEngine](#accountengine)
- [Cryptography](#cryptography)
  - [Key Generation](#key-generation)
  - [Encryption / Decryption](#encryption--decryption)
  - [Passphrase Encryption](#passphrase-encryption)
  - [Armored Encryption](#armored-encryption)
  - [Multi‑Recipient Encryption](#multi-recipient-encryption)
  - [Recipient Files](#recipient-files)
- [Domain Types](#domain-types)
  - [Fingerprint](#fingerprint)
  - [UserID](#userid)
  - [Identity](#identity)
  - [KeyGenData](#keygendata)
- [Error Handling](#error-handling)
- [Module Reference](#module-reference)
- [Testing](#testing)
- [Build and Lint](#build-and-lint)
- [Security Considerations](#security-considerations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

`age-credentials` replaces the old keyring‑manager design with a **pure account management engine**. It does not assume any storage layout, file format, or configuration structure. Instead, it provides:

- A trait `AccountBackend` that you implement to connect the engine to your own storage (filesystem, database, vault, memory, …).
- A stateless `AccountEngine` that performs all account operations (create, encrypt, decrypt, export, import, change passphrase, delete) using your backend.
- Strongly‑typed domain primitives (`Fingerprint`, `UserID`, `Identity`) with comprehensive validation.
- Full cryptographic operations through `librage` (age encryption), including multi‑recipient, passphrase, and armored encryption.
- Zeroization of secret keys and decrypted plaintext.
- Complete error propagation – no panics.

The library is a **framework/SDK**, not a turn‑key solution. You are expected to bring your own backend and storage.

---

## Architecture

```
src/
├── account/           Account engine (pure functions)
│   ├── engine.rs        AccountEngine::create_account, encrypt_for_account, …
├── backend/           Storage abstraction
│   └── traits.rs        AccountBackend trait
├── crypto/            Cryptographic operations (wraps librage)
│   ├── armor.rs         Armored encrypt/decrypt
│   ├── decrypt.rs       Binary decrypt
│   ├── encrypt.rs       Binary encrypt
│   ├── keygen.rs        Key pair generation
│   ├── passphrase.rs    Passphrase‑based encrypt/decrypt
│   ├── recipient.rs     Recipient file parsing
│   └── ascii.rs         Hex encoding/decoding
├── domain/            Data types and validation
│   ├── error.rs         AccountError enum
│   ├── fingerprint.rs   Fingerprint
│   ├── identity.rs      Identity struct
│   ├── types.rs         UserID, KeyGenData
│   └── validation.rs    Name & email validators
└── lib.rs
```

All modules are fully implemented.

---

## Installation

```toml
[dependencies]
age-credentials = "1.0.0"
```

Or via git:

```toml
[dependencies]
age-credentials = { git = "https://github.com/mroczect/age-credentials.git", tag = "v1.0.0" }
```

The crate requires Rust edition 2024.

---

## Dependencies

| Crate      | Version | Role                                         |
| ---------- | ------- | -------------------------------------------- |
| librage    | 1.1.0   | All age cryptographic operations             |
| age        | 0.12.1  | Public key validation (x25519 recipient)     |
| thiserror  | 2.0     | Error derive macro                           |
| serde      | 1       | Serialization framework                      |
| serde_json | 1       | JSON serialization for identity/metadata     |
| zeroize    | 1       | Secure zeroing of secret keys and plaintexts |
| sha2       | 0.11    | Fingerprint computation                      |
| chrono     | 0.4     | Timestamps (Identity.created_at)             |
| tempfile   | 3.27.0  | Atomic writes (example backend)              |
| toml       | 1.1.4   | TOML output helpers (optional usage)         |

---

## Quick Start

```rust
use age_credentials::account::AccountEngine;
use age_credentials::backend::traits::AccountBackend;
use age_credentials::domain::types::UserID;
use age_credentials::domain::fingerprint::Fingerprint;
use age_credentials::domain::identity::Identity;
use age_credentials::crypto::{generate_keypair, encrypt, decrypt};

// Implement AccountBackend for your storage (here a simple in‑memory mock)
struct MyBackend { /* ... */ }
impl AccountBackend for MyBackend { /* ... */ }

let mut backend = MyBackend::new();

// Create an account
let user = UserID::new("Alice", "alice@example.com")?;
let account = AccountEngine::create_account(&mut backend, user, "strong‑passphrase", None)?;

// Encrypt a message to Alice
let ciphertext = AccountEngine::encrypt_for_account(&backend, &account.fingerprint, b"Hello")?;

// Alice decrypts with her passphrase
let plaintext = AccountEngine::decrypt_for_account(
    &backend,
    &account.fingerprint,
    "strong‑passphrase",
    &ciphertext,
)?;
assert_eq!(*plaintext, b"Hello");
```

---

## Account System

### AccountBackend Trait

```rust
pub trait AccountBackend {
    fn save_identity(&mut self, identity: &Identity) -> Result<()>;
    fn load_identity(&self, fingerprint: &Fingerprint) -> Result<Option<Identity>>;
    fn delete_identity(&mut self, fingerprint: &Fingerprint) -> Result<()>;
    fn store_encrypted_private_key(&mut self, fingerprint: &Fingerprint, key: &[u8]) -> Result<()>;
    fn load_encrypted_private_key(&self, fp: &Fingerprint) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn list_fingerprints(&self) -> Result<Vec<Fingerprint>>;
    fn find_by_email(&self, email: &str) -> Result<Option<Fingerprint>> { ... }
}
```

Implement this trait for your storage. The default `find_by_email` iterates all identities; override it for efficiency.

### AccountEngine

A stateless struct providing all account operations as static methods:

- `create_account` – generates a key pair, encrypts the private key with a passphrase, and stores identity + encrypted key.
- `encrypt_for_account` – encrypts data to an account’s public key.
- `decrypt_for_account` – decrypts using the private key after unlocking it with the passphrase.
- `change_passphrase` – re‑encrypts the private key with a new passphrase.
- `export_account` / `import_account` – export/import an account as a passphrase‑encrypted hex blob.
- `delete_account` – removes identity and keys.
- `find_by_email`, `list_accounts` – search and enumeration.

All methods return `Result<_, AccountError>` and never panic.

---

## Cryptography

### Key Generation

```rust
let keypair = generate_keypair()?;
// keypair.public_key: String (age1…)
// keypair.secret_key: Zeroizing<String> (age‑secret‑key-1…)
```

### Encryption / Decryption

```rust
let ct = encrypt(b"plaintext", &public_key)?;
let pt = decrypt(&ct, &secret_key)?;
```

### Passphrase Encryption

```rust
let ct = encrypt_with_passphrase(b"data", "mypassword")?;
let pt = decrypt_with_passphrase(&ct, "mypassword")?;
```

Minimum passphrase length is 8 characters.

### Armored Encryption

```rust
let armored = encrypt_armored(b"data", &public_key)?;
// armored starts with "-----BEGIN AGE ENCRYPTED FILE-----"
```

Decrypt with the standard `decrypt()`.

### Multi‑Recipient Encryption

```rust
let ct = encrypt_multiple(b"data", &[&pk1, &pk2])?;
// can be decrypted with either sk1 or sk2
```

### Recipient Files

```rust
let recipients = read_recipients_from_file("recipients.txt")?;
// returns Vec<String> of age public keys
```

---

## Domain Types

### Fingerprint

A validated hex string (empty or non‑hex rejected). Used as the account identifier.

### UserID

```rust
let uid = UserID::new("Alice", "alice@example.com")?;
// validates name (2‑255 chars, allowed characters) and email (RFC‑like checks)
```

### Identity

```rust
pub struct Identity {
    pub fingerprint: Fingerprint,
    pub user_id: UserID,
    pub label: Option<String>,
    pub public_key: String,
    pub created_at: i64,
}
```

### KeyGenData

```rust
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
```

---

## Error Handling

All errors are variants of `AccountError` (enum defined in `domain::error`). Notable variants:

- `AccountNotFound`, `DuplicateAccount`
- `EncryptionFailed`, `DecryptionFailed`
- `KeyGenFailed`, `PassphraseTooShort`
- `InvalidData`, `Backend`, `Io`, `Serialization`

The library does not panic – all error paths return `Result`.

---

## Module Reference

| Module                | Description                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------- |
| `account::engine`     | `AccountEngine` – all account operations                                                  |
| `backend::traits`     | `AccountBackend` trait                                                                    |
| `crypto`              | All cryptographic functions (encrypt, decrypt, keygen, passphrase, armor, recipient, hex) |
| `domain::error`       | `AccountError` and `Result`                                                               |
| `domain::fingerprint` | `Fingerprint` type                                                                        |
| `domain::identity`    | `Identity` struct                                                                         |
| `domain::types`       | `UserID`, `KeyGenData`                                                                    |
| `domain::validation`  | Name and email validators                                                                 |

---

## Testing

The test suite covers:

- **Crypto**: keygen, encrypt/decrypt round‑trips, multi‑recipient, passphrase, armored, error conditions.
- **Account engine**: create, find, encrypt/decrypt, change passphrase, export/import, delete, list – all using a mock backend.
- **Types**: fingerprint, user ID validation, serialization.

Run tests:

```bash
cargo test
```

---

## Build and Lint

```bash
make ci   # runs fmt check, clippy, and tests
```

---

## Security Considerations

- **Secret keys are zeroized** on drop.
- **Passphrase minimum length** is enforced.
- **No unwrap/panic** in production code.
- **Cryptographic operations** are delegated to librage (rage‑lib).
- **Public keys** are validated via age’s x25519 parser.
- **Backend storage** is under your control – you decide how to protect keys at rest.

---

## Roadmap

- Example filesystem backend implementation.
- Support for custom metadata on accounts.
- Account status (active, suspended, revoked).
- Role‑based access helpers.
- Integration with `libvctrl` for versioned account storage.
- More extensive integration tests.

---

## License

MIT License. See [LICENSE](LICENSE).
