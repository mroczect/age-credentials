# age-credentials

Identity and credential management built on the age encryption format.

age-credentials is a Rust library that provides GnuPG-like identity management --
user IDs, keyrings, passphrase protection, configuration persistence, and
structured metadata -- on top of the simplicity and security of the age
encryption specification. It is designed for developers who need programmatic
control over age identities and credentials without depending on a CLI tool or
the GnuPG runtime.

This crate is a library only. It does not ship a binary.

**Status:** Active development. Not yet ready for production use. The public
API may change before version 1.0. This library is not published on crates.io.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Dependencies](#dependencies)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [ConfigLoader](#configloader)
  - [KeyringPath](#keyringpath)
- [Cryptography](#cryptography)
  - [Key Generation](#key-generation)
  - [Encryption](#encryption)
  - [Decryption](#decryption)
  - [Multi-Recipient Encryption](#multi-recipient-encryption)
  - [Armored Encryption](#armored-encryption)
  - [Passphrase Encryption](#passphrase-encryption)
  - [Recipient Files](#recipient-files)
- [Key Management API](#key-management-api)
  - [Public Key Operations](#public-key-operations)
  - [Private Key Operations](#private-key-operations)
  - [Public Key Validation](#public-key-validation)
- [Type System](#type-system)
  - [Fingerprint](#fingerprint)
  - [UserID](#userid)
  - [Name Validation](#name-validation)
  - [Email Validation](#email-validation)
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
- [Build and Lint](#build-and-lint)
- [Security Considerations](#security-considerations)
- [Migration from v0.1.0](#migration-from-v010)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

age-credentials sits on top of two complementary crates:

- [librage](https://github.com/mroczect/librage) -- A safe Rust wrapper around
  the [rage](https://str4d.dev/rage) implementation of the
  [age](https://age-encryption.org) encryption specification. All cryptographic
  operations (key generation, encryption, decryption) delegate to librage.
- [age](https://crates.io/crates/age) (v0.12.1) -- The reference Rust age
  library. Used specifically for its `age::x25519::Recipient` parser to validate
  public key strings before they are written to or read from disk.

While age and rage provide excellent file-level encryption through their
command-line interfaces, they do not offer a built-in concept of identity
management, keyrings, or user metadata. age-credentials fills that gap by
providing:

- A keyring directory layout with dedicated subdirectories for private and
  public keys, and a JSON metadata file tracking identities and the default
  identity.
- Atomic metadata persistence using temporary files, preventing corruption on
  crash or power loss.
- Strongly-typed identity primitives (Fingerprint, UserID, Identity, Metadata)
  with comprehensive validation.
- Cryptographic operations with full error propagation and reporting.
- Passphrase-based encryption with a minimum length policy.
- Multi-recipient encryption for sharing secrets across a team.
- Armored output for embedding ciphertext in text-based protocols.
- Recipient file parsing for reading `.age-recipients` style files.
- Zeroized secret key and private key types that overwrite their memory on
  drop.
- Public key I/O with structural validation using the age x25519 recipient
  parser.
- Private key I/O with zeroized read buffers.

---

## Architecture

The crate is organized into three top-level modules, each with sub-modules:

```
src/
  lib.rs              Crate root, re-exports all public modules
  config/             Configuration loading, saving, and path management
    mod.rs              Declares and re-exports loader and path
    loader.rs           ConfigLoader: load and save Metadata JSON files
    path.rs             KeyringPath: keyring directory layout management
  core/               Core business logic
    mod.rs              Declares and re-exports api, crypto, and output
    api/                Key management I/O operations
      mod.rs              Declares and re-exports private_keys and public_keys
      private_keys.rs     Read and write encrypted private key files
      public_keys.rs      Read, write, and validate public key files
    crypto/            Cryptographic operations (all delegate to librage)
      mod.rs              Declares and re-exports all crypto sub-modules
      armor.rs            Armored encryption
      decrypt.rs          Decryption
      encrypt.rs          Encryption
      keygen.rs           Key pair generation
      passphrase.rs       Passphrase-based encryption and decryption
      recipient.rs        Recipient file parsing
    output/            Output formatting (placeholders)
      mod.rs              Declares ascii, json, toml
      ascii.rs            Placeholder
      json.rs             Placeholder
      toml.rs             Placeholder
  handler/            Shared infrastructure
    mod.rs              Declares and re-exports error and types
    error.rs            AgeCredentialsError enum and Result alias
    types.rs            Core data types and validation functions
```

The `handler` module is consumed by `config` and `core`. The `config` and
`core::crypto` and `core::api` modules are fully implemented. The
`core::output` sub-modules remain placeholders.

---

## Installation

This library is not published on crates.io. Add it to your `Cargo.toml` using
the git repository URL:

```toml
[dependencies]
age-credentials = { git = "https://github.com/mroczect/age-credentials.git" }
```

To pin a specific revision:

```toml
[dependencies]
age-credentials = { git = "https://github.com/mroczect/age-credentials.git", rev = "..." }
```

The crate edition is 2024 and requires a Rust toolchain that supports that
edition.

---

## Dependencies

Runtime dependencies:

| Crate              | Version                | Role                                                            |
| ------------------ | ---------------------- | --------------------------------------------------------------- |
| librage            | git (mroczect/librage) | Delegates all age encrypt/decrypt/keygen operations             |
| age                | 0.12.1                 | Parses and validates age x25519 recipient public keys           |
| thiserror          | 2.0                    | Provides the Error derive macro for AgeCredentialsError         |
| serde              | 1 (derive feature)     | Serialization framework for types and metadata                  |
| serde_json         | 1                      | JSON serialization and deserialization for metadata persistence |
| zeroize            | 1 (serde feature)      | Secure zeroing of secret key and private key memory on drop     |
| dirs               | 6                      | Resolves platform-specific config and data directories          |
| sha2               | 0.11                   | SHA-2 hashing for fingerprint computation                       |
| eyre               | 0.6.12                 | Ergonomic error reporting                                       |
| color-eyre         | 0.6.5                  | Colored terminal error reports                                  |
| tracing            | 0.1.44                 | Structured log emission                                         |
| tracing-subscriber | 0.3.23                 | Configures the tracing subscriber                               |
| tempfile           | 3.27.0                 | Atomic file writes in ConfigLoader::save via NamedTempFile      |

Development dependencies: none. (tempfile was promoted to a runtime dependency
in v0.2.0.)

---

## Quick Start

```rust
use age_credentials::core::crypto::*;
use age_credentials::config::{ConfigLoader, KeyringPath};

// Generate a key pair
let keypair = generate_keypair().expect("key generation failed");

// Encrypt and decrypt
let plaintext = b"Hello, age-credentials!";
let ciphertext = encrypt(plaintext, &keypair.public_key).expect("encryption failed");
let decrypted = decrypt(&ciphertext, &keypair.secret_key).expect("decryption failed");
assert_eq!(decrypted, plaintext);

// Create a keyring directory structure
let keyring = KeyringPath::new("/home/user/.age-credentials/keyring").expect("keyring init failed");

// Save metadata atomically
let meta = age_credentials::handler::types::Metadata::default();
ConfigLoader::save(keyring.metadata_file(), &meta).expect("save failed");

// Load metadata back
let loaded = ConfigLoader::load(keyring.metadata_file()).expect("load failed");
assert!(loaded.identities.is_empty());
```

---

## Configuration

The `config` module provides two components: `ConfigLoader` for persisting and
reading metadata, and `KeyringPath` for managing the keyring directory layout.
Both are re-exported at the crate root.

### ConfigLoader

```rust
use age_credentials::ConfigLoader;
// or: use age_credentials::config::ConfigLoader;
```

`ConfigLoader` is a unit struct with two associated functions. It has no state
and cannot be instantiated. All operations are called as
`ConfigLoader::load(...)` and `ConfigLoader::save(...)`.

#### ConfigLoader::load

```rust
pub fn load(path: impl AsRef<Path>) -> Result<Metadata>
```

Reads a JSON metadata file from disk and deserializes it into a `Metadata`
value.

**Behavior in detail:**

1. Reads the entire file into a string using `std::fs::read_to_string`. If the
   file cannot be read (for example, it does not exist or permissions deny
   access), returns `Err(AgeCredentialsError::Io)` with the path and the
   underlying `std::io::Error`.
2. Checks the size of the read data against the constant `MAX_METADATA_SIZE`,
   which is set to 5 MiB (5,242,880 bytes). If the file exceeds this limit,
   returns `Err(AgeCredentialsError::InvalidData)` with context
   `"metadata file"` and details including the actual size and the maximum.
   This guard prevents unbounded memory allocation when reading untrusted files.
3. Deserializes the string as JSON into a `Metadata` value using
   `serde_json::from_str`. If the JSON is malformed or does not match the
   `Metadata` schema, returns `Err(AgeCredentialsError::Serialization)` with
   target `"metadata"`, the path, and the underlying `serde_json::Error`.

**Example:**

```rust
use age_credentials::ConfigLoader;

let metadata = ConfigLoader::load("/home/user/.age-credentials/keyring/metadata.json")?;
for identity in &metadata.identities {
    println!("{}: {}", identity.fingerprint, identity.user_id.to_formatted());
}
```

#### ConfigLoader::save

```rust
pub fn save(path: impl AsRef<Path>, metadata: &Metadata) -> Result<()>
```

Serializes a `Metadata` value to pretty-printed JSON and writes it atomically
to the target path.

**Behavior in detail:**

1. Serializes the metadata to a pretty-printed JSON string using
   `serde_json::to_string_pretty`. If serialization fails, returns
   `Err(AgeCredentialsError::Serialization)` with target `"metadata"`, the
   path, and the underlying error.
2. Determines the parent directory of the target path using `Path::parent`. If
   the path has no parent (for example, a bare filename with no directory
   component), returns `Err(AgeCredentialsError::Config)` with message
   `"Metadata path has no parent directory"` and location set to the source
   file where the error originated.
3. Creates a `tempfile::NamedTempFile` in the parent directory. If the
   temporary file cannot be created, returns `Err(AgeCredentialsError::Io)`.
4. Writes the JSON bytes to the temporary file. If the write fails, returns
   `Err(AgeCredentialsError::Io)`.
5. Persists the temporary file to the target path using `NamedTempFile::persist`.
   This is an atomic rename on POSIX systems and an atomic replace on Windows.
   If the persist operation fails, returns `Err(AgeCredentialsError::Io)` with
   the underlying error from the persist failure.

**Why atomic writes matter:** If the process crashes or the machine loses power
during a non-atomic write, the metadata file may be left in a partially-written
state, making it unreadable on next load. By writing to a temporary file first
and then atomically renaming it to the final path, the metadata file is always
in a consistent state: either the old version or the new version, never a
partial write.

**Example:**

```rust
use age_credentials::{ConfigLoader, Metadata, Identity, Fingerprint, UserID};
use std::path::Path;

let mut meta = Metadata::default();
meta.identities.push(Identity {
    fingerprint: Fingerprint::new("abc123").unwrap(),
    user_id: UserID::new("Alice Smith", "alice@example.com").unwrap(),
    label: Some("work".into()),
    private_key_path: "/home/user/.age-credentials/keyring/private/abc123.age".into(),
    public_key_path: "/home/user/.age-credentials/keyring/public/abc123.pub".into(),
    created_at: 1700000000,
});

ConfigLoader::save("/home/user/.age-credentials/keyring/metadata.json", &meta)?;
```

### KeyringPath

```rust
use age_credentials::KeyringPath;
// or: use age_credentials::config::KeyringPath;
```

`KeyringPath` manages the directory layout of a keyring on disk. It is a
struct containing a single private field `root: PathBuf` that holds the
absolute path to the keyring root directory.

#### KeyringPath::new

```rust
pub fn new(path: impl AsRef<Path>) -> Result<Self>
```

Creates a new keyring at the given path. This function:

1. Validates that the path is not empty. Returns `Err(AgeCredentialsError::Config)`
   with message `"Keyring path cannot be empty"` if it is.
2. Creates the root directory and all parent directories using
   `std::fs::create_dir_all`. Returns `Err(AgeCredentialsError::Io)` on
   failure.
3. Resolves the path to an absolute path using `std::fs::canonicalize`.
   Returns `Err(AgeCredentialsError::Io)` on failure. Note: canonicalize
   requires that the path exists on the filesystem, which it does after the
   preceding `create_dir_all` call.
4. Creates the `private/` subdirectory inside the root.
5. Creates the `public/` subdirectory inside the root.
6. Returns `Ok(KeyringPath { root: absolute })`.

After calling `new`, the following directory structure exists on disk:

```
{path}/
  private/
  public/
```

#### KeyringPath::open_existing

```rust
pub fn open_existing(path: impl AsRef<Path>) -> Result<Self>
```

Opens an existing keyring directory without creating any directories. This
function:

1. Checks whether the path is a directory using `Path::is_dir`. If it is not,
   returns `Err(AgeCredentialsError::Config)` with message
   `"Keyring directory not found: {path}"`.
2. Resolves the path to an absolute path using `std::fs::canonicalize`.
3. Returns `Ok(KeyringPath { root: absolute })`.

This function does not verify that the `private/` and `public/` subdirectories
exist. It only checks that the root directory exists.

#### KeyringPath accessor methods

```rust
pub fn metadata_file(&self) -> PathBuf
```

Returns the path to the metadata file: `{root}/metadata.json`.

```rust
pub fn private_dir(&self) -> PathBuf
```

Returns the path to the private key directory: `{root}/private`.

```rust
pub fn public_dir(&self) -> PathBuf
```

Returns the path to the public key directory: `{root}/public`.

```rust
pub fn fingerprint_private_path(&self, fingerprint: &str) -> PathBuf
```

Returns the path to a private key file for the given fingerprint:
`{root}/private/{fingerprint}.age`.

```rust
pub fn fingerprint_public_path(&self, fingerprint: &str) -> PathBuf
```

Returns the path to a public key file for the given fingerprint:
`{root}/public/{fingerprint}.pub`.

**Example:**

```rust
use age_credentials::KeyringPath;

let kr = KeyringPath::new("/home/user/.age-credentials/keyring")?;

// Paths
assert_eq!(kr.metadata_file(), PathBuf::from("/home/user/.age-credentials/keyring/metadata.json"));
assert_eq!(kr.private_dir(), PathBuf::from("/home/user/.age-credentials/keyring/private"));
assert_eq!(kr.public_dir(), PathBuf::from("/home/user/.age-credentials/keyring/public"));
assert_eq!(kr.fingerprint_private_path("abc123"), PathBuf::from("/home/user/.age-credentials/keyring/private/abc123.age"));
assert_eq!(kr.fingerprint_public_path("abc123"), PathBuf::from("/home/user/.age-credentials/keyring/public/abc123.pub"));

// Open an existing keyring (no directory creation)
let kr2 = KeyringPath::open_existing("/home/user/.age-credentials/keyring")?;
```

---

## Cryptography

All cryptographic functions live under `age_credentials::core::crypto`. The
module re-exports every public function from its sub-modules, so you can import
them directly:

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

Generates a new age key pair by calling `librage::generate_keypair`. The
returned `KeyGenData` contains:

- `public_key: String` -- The age public key string, starting with `age1`.
- `secret_key: Zeroizing<String>` -- The age secret key string, wrapped in
  `Zeroizing` so that the underlying memory is overwritten with zeroes when the
  value is dropped.

If librage reports failure, the function returns `Err(AgeCredentialsError::KeyGenFailed)`.
If librage reports success but provides no data, the same error variant is
returned with a message indicating the absence of data.

### Encryption

```rust
pub fn encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>>
```

Encrypts the given plaintext bytes to a single public key. Validates that the
public key is non-empty before calling librage. If the public key is empty,
returns `Err(AgeCredentialsError::InvalidData)` with context `"encrypt"` and
details `"public key is empty"`.

On librage failure, returns `Err(AgeCredentialsError::EncryptionFailed)`
containing the recipient, the error code, and the error message.

On success, the ciphertext is returned as a `Vec<u8>`.

```rust
pub fn encrypt_multiple(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>>
```

Encrypts the given plaintext bytes to one or more public keys. Validates that
the `public_keys` slice is non-empty. If the slice is empty, returns
`Err(AgeCredentialsError::InvalidData)` with context `"encrypt multiple"` and
details `"at least one public key required"`.

On librage failure, returns `Err(AgeCredentialsError::EncryptionFailed)`
containing the list of recipients, the error code, and the error message.

On librage success with no data, returns `Err(AgeCredentialsError::EncryptionFailed)`
with code `"UNKNOWN"` and message `"librage returned success but no data"`.

### Decryption

```rust
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>>
```

Decrypts the given ciphertext using the provided secret key. Validates that the
secret key is non-empty. If the secret key is empty, returns
`Err(AgeCredentialsError::InvalidData)` with context `"decrypt"` and details
`"secret key is empty"`.

This function handles both binary and armored ciphertext transparently because
librage detects the format automatically.

On librage failure, returns `Err(AgeCredentialsError::DecryptionFailed)` with
`identity: None`, a hint suggesting the user verify the secret key or
ciphertext integrity, and the error code and message from librage.

On success, the plaintext is returned as a `Vec<u8>`.

### Multi-Recipient Encryption

Multi-recipient encryption produces a single ciphertext that can be decrypted
by any one of the corresponding secret keys. This is useful for sharing a
secret with a group without creating separate ciphertexts for each member.

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

These functions behave identically to `encrypt` and `encrypt_multiple` except
that the output is ASCII-armored. The returned bytes begin with the header
`-----BEGIN AGE ENCRYPTED FILE-----`. Armored output is suitable for embedding
in email, JSON fields, environment variables, or any text-based transport.

Armored ciphertext can be decrypted using the same `decrypt` function. librage
detects the armored format and handles it transparently.

### Passphrase Encryption

```rust
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>>
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>>
```

These functions encrypt and decrypt using a passphrase instead of a public/secret
key pair. They are subject to a minimum passphrase length of 8 characters,
enforced before any call to librage.

If the passphrase is shorter than 8 characters, the function returns
`Err(AgeCredentialsError::PassphraseTooShort)` containing the provided length
and the minimum length.

Example:

```rust
let ciphertext = encrypt_with_passphrase(b"sensitive data", "a-strong-passphrase")?;
let plaintext = decrypt_with_passphrase(&ciphertext, "a-strong-passphrase")?;
assert_eq!(plaintext, b"sensitive data");
```

### Recipient Files

```rust
pub fn read_recipients_from_file(path: impl AsRef<Path>) -> Result<Vec<String>>
```

Reads a recipient list from a text file. The file format follows the convention
used by age:

- Each line is treated as a recipient public key.
- Lines starting with `#` are comments and are skipped.
- Blank lines (or lines that are only whitespace) are skipped.
- Every non-comment, non-blank line must start with the string `age`. If a
  line does not, the function returns `Err(AgeCredentialsError::InvalidData)`
  with context `"recipient file"` and details indicating the line number and
  the offending content.
- If no valid recipients are found in the file, returns
  `Err(AgeCredentialsError::InvalidData)` with details
  `"No valid recipient found in file"`.
- I/O errors when opening or reading the file are returned as
  `Err(AgeCredentialsError::Io)` with the file path and the underlying
  `std::io::Error`.

Example recipient file:

```
# Team members
age1qyqszqgp7y9y9l9w9rw9r6jg2w3q4szqgp7y9y9l9w9rw9r6jg2w3q4szqgp
age1abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678
```

---

## Key Management API

The `core::api` module provides I/O operations for reading and writing key
files to disk. It is re-exported through `core` and at the crate root.

```rust
use age_credentials::core::api::{
    read_public_key, write_public_key,
    read_encrypted_private_key, write_encrypted_private_key,
};
// or: use age_credentials::api::*;
```

### Public Key Operations

#### read_public_key

```rust
pub fn read_public_key(path: impl AsRef<Path>) -> Result<String>
```

Reads a public key from a file. This function:

1. Reads the entire file as a string using `std::fs::read_to_string`.
2. Trims leading and trailing whitespace from the content. This handles files
   that contain a trailing newline.
3. Validates the trimmed string by attempting to parse it as an
   `age::x25519::Recipient`. See [Public Key Validation](#public-key-validation)
   for details.
4. Returns the trimmed, validated key string on success.

If the file cannot be read, returns `Err(AgeCredentialsError::Io)`. If the
content is empty after trimming or fails recipient parsing, returns
`Err(AgeCredentialsError::InvalidData)`.

#### write_public_key

```rust
pub fn write_public_key(path: impl AsRef<Path>, public_key: &str) -> Result<()>
```

Writes a public key to a file. This function:

1. Validates the public key string by attempting to parse it as an
   `age::x25519::Recipient`. See [Public Key Validation](#public-key-validation)
   for details.
2. Writes the key to the file with a trailing newline appended.

Validation is performed before any file I/O. This ensures that invalid keys are
never written to disk, maintaining the integrity of the keyring directory.

If the key string is empty or fails recipient parsing, returns
`Err(AgeCredentialsError::InvalidData)`. If the file write fails, returns
`Err(AgeCredentialsError::Io)`.

**Round-trip example:**

```rust
use age_credentials::api::*;
use age_credentials::core::crypto::generate_keypair;

let kp = generate_keypair()?;
write_public_key("/path/to/key.pub", &kp.public_key)?;
let read_back = read_public_key("/path/to/key.pub")?;
assert_eq!(read_back, kp.public_key);
```

### Private Key Operations

#### read_encrypted_private_key

```rust
pub fn read_encrypted_private_key(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>>
```

Reads the raw bytes of an encrypted private key file and returns them wrapped
in `Zeroizing<Vec<u8>>`. The `Zeroizing` wrapper ensures that the byte buffer
is overwritten with zeroes when the value is dropped, reducing the window
during which key material is exposed in memory.

This function does not decrypt the key. It reads the file as-is, which is
expected to contain the key in an encrypted form (for example, encrypted with
a passphrase or a master key).

If the file cannot be read, returns `Err(AgeCredentialsError::Io)`.

#### write_encrypted_private_key

```rust
pub fn write_encrypted_private_key(path: impl AsRef<Path>, encrypted_key: &[u8]) -> Result<()>
```

Writes encrypted private key bytes to a file. Validates that the data is
non-empty before writing. If the data is empty, returns
`Err(AgeCredentialsError::InvalidData)` with context
`"encrypted private key write"` and details `"Encrypted key data is empty"`.

If the file write fails, returns `Err(AgeCredentialsError::Io)`.

**Round-trip example:**

```rust
use age_credentials::api::*;

let encrypted_key_data = vec![1, 2, 3, 4, 5]; // In practice, this would be ciphertext
write_encrypted_private_key("/path/to/key.age", &encrypted_key_data)?;
let read_back = read_encrypted_private_key("/path/to/key.age")?;
assert_eq!(*read_back, encrypted_key_data);
```

### Public Key Validation

```rust
fn validate_public_key_string(key: &str) -> Result<()>
```

This is an internal function (not publicly exported) used by both
`read_public_key` and `write_public_key`. It performs two checks:

1. **Empty check:** If the key string is empty, returns
   `Err(AgeCredentialsError::InvalidData)` with context `"public key"` and
   details `"Public key is empty"`.
2. **Structural validation:** Attempts to parse the string as an
   `age::x25519::Recipient` using the `str::parse` method. The `age` crate's
   `Recipient` parser validates that the string begins with `age1` and that the
   remaining characters form a valid Bech32 encoding of an x25519 public key.
   If parsing fails, returns `Err(AgeCredentialsError::InvalidData)` with
   context `"public key"` and details
   `"Invalid age public key: {key}"`.

This validation is stronger than the simple prefix check performed by the
recipient file parser (`read_recipients_from_file`), which only checks that a
line starts with `"age"`. The `age::x25519::Recipient` parser performs full
Bech32 decoding and key validation.

---

## Type System

All types live under `age_credentials::handler::types` and are re-exported at
the crate root and through the `handler` module.

### Fingerprint

```rust
pub struct Fingerprint(String);
```

A validated hexadecimal string used to uniquely identify an age key pair. The
inner `String` is private and cannot be accessed directly. Construction is
performed through the `new` method, which rejects:

- Empty strings.
- Strings containing characters that are not ASCII hex digits (0-9, a-f, A-F).

The type implements `Debug`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Serialize`,
`Deserialize`, and `Display` (where Display yields the inner hex string).

```rust
use age_credentials::Fingerprint;

let fp = Fingerprint::new("a1b2c3d4e5f6")?;
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

A validated user identity consisting of a name and an email address.

#### UserID::new

```rust
pub fn new(
    name: impl Into<String>,
    email: impl Into<String>,
) -> Result<Self, AgeCredentialsError>
```

Constructs a `UserID` after validating the name and email. Both values are
trimmed of leading and trailing whitespace before validation and storage. The
validation rules are described in the [Name Validation](#name-validation) and
[Email Validation](#email-validation) sections below.

#### UserID::to_formatted

```rust
pub fn to_formatted(&self) -> String
```

Returns the standard OpenPGP-style string representation: `Name <email>`.

```rust
use age_credentials::UserID;

let uid = UserID::new("Alice Smith", "alice@example.com")?;
assert_eq!(uid.to_formatted(), "Alice Smith <alice@example.com>");

// Whitespace is trimmed automatically
let uid2 = UserID::new("  Alice  ", "  alice@example.com  ")?;
assert_eq!(uid2.name, "Alice");
assert_eq!(uid2.email, "alice@example.com");
```

The type implements `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, and
`Deserialize`.

### Name Validation

```rust
pub fn validate_user_name(name: &str) -> Result<(), AgeCredentialsError>
```

A standalone function that applies name validation rules without constructing a
`UserID`. Returns `Ok(())` on success or `Err(AgeCredentialsError::InvalidUserId)`
on failure.

**Rules applied in order:**

1. The name is trimmed of leading and trailing whitespace.
2. The trimmed name must not be empty. Error: `"Name cannot be empty"`.
3. The trimmed name must be at least 2 characters long. Error:
   `"Name too short: {n} chars, minimum 2"`.
4. The trimmed name must be at most 255 characters long. Error:
   `"Name too long: {n} chars, maximum 255"`.
5. Every character in the trimmed name must be one of:
   - An alphabetic character (Unicode General Category L, includes letters
     with diacritics).
   - A numeric digit.
   - A space (`' '`).
   - A hyphen (`'-'`).
   - An apostrophe (`'\''`).
   - A period (`'.'`).
     If any other character is found, error:
     `"Invalid character '{c}' at position {i} in name"` (position is 1-indexed).

**Examples of valid names:**

- `"Alice"`
- `"Bob O'Connor"`
- `"Jean-Luc Picard"`
- `"Dr. Smith"`
- `"Mar1a"`

**Examples of invalid names:**

- `"A"` -- too short (1 character, minimum 2)
- `""` -- empty after trimming
- `"Alice!"` -- exclamation mark is not an allowed character
- `"Alice@Work"` -- at-sign is not an allowed character
- A string longer than 255 characters after trimming

### Email Validation

```rust
pub fn validate_user_email(email: &str) -> Result<(), AgeCredentialsError>
```

A standalone function that applies email validation rules without constructing
a `UserID`. Returns `Ok(())` on success or
`Err(AgeCredentialsError::InvalidUserId)` on failure.

**Rules applied in order:**

1. The email is trimmed of leading and trailing whitespace.
2. The trimmed email must not be empty. Error: `"Email cannot be empty"`.
3. The trimmed email must be at most 254 characters long (per RFC 5321). Error:
   `"Email too long: {n} chars, maximum 254"`.
4. The trimmed email must contain exactly one `@` character. Error:
   `"Email must contain exactly one '@'"`.
5. The local part (before `@`) and the domain (after `@`) must both be
   non-empty. Error: `"Email local part or domain is empty"`.
6. Every character in the trimmed email must be one of:
   - An alphanumeric character.
   - A period (`'.'`).
   - A hyphen (`'-'`).
   - An underscore (`'_'`).
   - The at-sign (`'@'`).
   - A plus sign (`'+'`).
     If any other character is found, error:
     `"Invalid character '{c}' at position {i} in email"` (position is 1-indexed).

**Examples of valid emails:**

- `"alice@example.com"`
- `"a.b+c@d-e.net"`
- `"user_name@domain.org"`

**Examples of invalid emails:**

- `""` -- empty after trimming
- `"no-at-sign"` -- does not contain `@`
- `"a@b@c.com"` -- contains more than one `@`
- `"@domain.com"` -- empty local part
- `"user@"` -- empty domain
- `"user@domain.c om"` -- space is not an allowed character
- A string longer than 254 characters after trimming

**Limitations:** This validation is sufficient for most practical purposes but
does not constitute full RFC 5322 conformance. It does not validate:

- Quoted strings in the local part.
- IP address literals in the domain (for example, `user@[192.168.1.1]`).
- Domain existence or MX records.
- Internationalized email addresses (EAI, RFC 6531).

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
- `label` -- An optional human-readable label for organizational purposes
  (for example, `"work"` or `"personal"`).
- `private_key_path` -- The filesystem path where the encrypted secret key
  file is stored.
- `public_key_path` -- The filesystem path where the public key file is
  stored.
- `created_at` -- Unix timestamp (seconds since epoch) of when the identity
  was created.

This struct does not perform validation on construction. Validation is
delegated to `Fingerprint::new` and `UserID::new` when building the
constituent fields.

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
- `default_identity` -- The fingerprint of the identity that should be used
  when no explicit identity is specified. This may be `None`.

Implements `Default` (empty identity list, no default), `Debug`, `Clone`,
`Serialize`, and `Deserialize`.

The `Metadata` struct is the unit of persistence for `ConfigLoader`. When
saved to disk, it is serialized as pretty-printed JSON. When loaded from disk,
it is deserialized from JSON with a 5 MiB size limit.

```rust
use age_credentials::{Metadata, Identity, Fingerprint, UserID};

let mut meta = Metadata::default();
let ident = Identity {
    fingerprint: Fingerprint::new("abc123")?,
    user_id: UserID::new("Alice", "alice@example.com")?,
    label: Some("work".into()),
    private_key_path: "/home/user/.age-credentials/keyring/private/abc123.age".into(),
    public_key_path: "/home/user/.age-credentials/keyring/public/abc123.pub".into(),
    created_at: 1700000000,
};
meta.identities.push(ident);
meta.default_identity = Some(Fingerprint::new("abc123")?);
```

### KeyGenData

```rust
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
```

The return type of `generate_keypair`. The `secret_key` field is wrapped in
`Zeroizing<String>` from the `zeroize` crate. When the `KeyGenData` value is
dropped, the secret key string is overwritten with zeroes in memory before
deallocation. This reduces the window during which the secret key material is
exposed in RAM.

The `Zeroizing` wrapper also supports serialization through the `serde`
feature of the `zeroize` crate, which is enabled in this project's
Cargo.toml.

---

## Error Handling

All fallible operations in age-credentials return
`handler::error::Result<T>`, which is an alias for
`std::result::Result<T, AgeCredentialsError>`.

### Error Variants

The `AgeCredentialsError` enum is defined with `thiserror` and implements
`std::error::Error`, `Debug`, and `Display`. Each variant produces a
human-readable error message through the `#[error(...)]` attribute.

| Variant               | Fields                                                                        | Display format                                                                   |
| --------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `Io`                  | `path: PathBuf`, `source: std::io::Error`                                     | `I/O error at {path}: {source}`                                                  |
| `Serialization`       | `target: &'static str`, `path: PathBuf`, `source: serde_json::Error`          | `Serialization error for {target} at {path}: {source}`                           |
| `DuplicateIdentity`   | `fingerprint: String`, `keyring_path: PathBuf`                                | `Duplicate identity {fingerprint} in keyring at {keyring_path}`                  |
| `IdentityNotFound`    | `search_key: String`, `keyring_path: PathBuf`                                 | `Identity not found: {search_key} in keyring at {keyring_path}`                  |
| `InvalidEmail`        | `email: String`                                                               | `Invalid email address: {email}`                                                 |
| `InvalidName`         | `name: String`                                                                | `Invalid name: {name}`                                                           |
| `PassphraseIncorrect` | `identity: String`                                                            | `Passphrase incorrect for identity {identity}`                                   |
| `EncryptionFailed`    | `recipients: Vec<String>`, `code: String`, `message: String`                  | `Encryption failed for recipients {recipients:?}: [{code}] {message}`            |
| `DecryptionFailed`    | `identity: Option<String>`, `hint: String`, `code: String`, `message: String` | `Decryption failed for identity {identity:?} (hint: {hint}): [{code}] {message}` |
| `KeyGenFailed`        | `reason: String`                                                              | `Key generation failed: {reason}`                                                |
| `MetadataNotFound`    | `path: PathBuf`                                                               | `Metadata file not found at {path}`                                              |
| `InvalidData`         | `context: &'static str`, `details: String`                                    | `Invalid data in {context}: {details}`                                           |
| `Config`              | `message: String`, `location: String`                                         | `Configuration error: {message} (at {location})`                                 |
| `PassphraseTooShort`  | `length: usize`, `min_length: usize`                                          | `Passphrase too short: {length} chars, minimum {min_length}`                     |
| `InvalidFingerprint`  | `reason: String`                                                              | `Invalid fingerprint: {reason}`                                                  |
| `InvalidUserId`       | `reason: String`                                                              | `Invalid User ID: {reason}`                                                      |

### Result Type Alias

```rust
pub type Result<T> = std::result::Result<T, AgeCredentialsError>;
```

This alias is exported at the crate root. Use it in your own functions that
propagate age-credentials errors:

```rust
use age_credentials::Result;

fn my_operation() -> Result<String> {
    let kp = age_credentials::core::crypto::generate_keypair()?;
    Ok(kp.public_key)
}
```

### Pattern Matching Errors

Because `AgeCredentialsError` is an enum, you can match on specific variants
to implement conditional logic or user-facing messaging:

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

---

## Module Reference

| Module path               | Status      | Description                                                                                                                                           |
| ------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config`                  | Implemented | Top-level configuration module. Declares and re-exports `loader` and `path`.                                                                          |
| `config::loader`          | Implemented | `ConfigLoader::load` and `ConfigLoader::save` for metadata JSON persistence with atomic writes and a 5 MiB size limit.                                |
| `config::path`            | Implemented | `KeyringPath` for keyring directory layout management: creation, opening, and path resolution.                                                        |
| `core`                    | Implemented | Top-level core module. Declares and re-exports `api`, `crypto`, and `output`.                                                                         |
| `core::api`               | Implemented | Key management I/O. Declares and re-exports `private_keys` and `public_keys`.                                                                         |
| `core::api::private_keys` | Implemented | `read_encrypted_private_key` and `write_encrypted_private_key` for encrypted private key file I/O with zeroized read buffers.                         |
| `core::api::public_keys`  | Implemented | `read_public_key` and `write_public_key` for public key file I/O with structural validation via `age::x25519::Recipient`.                             |
| `core::crypto`            | Implemented | All cryptographic operations. Re-exports `armor`, `decrypt`, `encrypt`, `keygen`, `passphrase`, `recipient`.                                          |
| `core::output`            | Partial     | Output formatting. Declares `ascii`, `json`, `toml`. None have implementations.                                                                       |
| `core::output::ascii`     | Placeholder | ASCII output formatting. No public API yet.                                                                                                           |
| `core::output::json`      | Placeholder | JSON output formatting. No public API yet.                                                                                                            |
| `core::output::toml`      | Placeholder | TOML output formatting. No public API yet.                                                                                                            |
| `handler`                 | Implemented | Shared infrastructure. Declares and re-exports `error` and `types`.                                                                                   |
| `handler::error`          | Implemented | The `AgeCredentialsError` enum and `Result` alias.                                                                                                    |
| `handler::types`          | Implemented | Core data types and validation functions: `Fingerprint`, `UserID`, `Identity`, `Metadata`, `KeyGenData`, `validate_user_name`, `validate_user_email`. |

The crate root (`lib.rs`) declares `config`, `core`, and `handler` as public
modules and re-exports all their contents with `pub use`. This means you can
access types and functions from the crate root or through their full module
path:

```rust
// All equivalent
use age_credentials::ConfigLoader;
use age_credentials::config::ConfigLoader;
use age_credentials::config::loader::ConfigLoader;
```

---

## Testing

The test suite contains 62 tests across 5 files. All tests pass.

### api_tests (5 tests)

| Test name                                   | What it verifies                                                                                            |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `test_write_and_read_public_key`            | Writing a valid public key and reading it back produces the same key string                                 |
| `test_write_public_key_invalid`             | Writing an invalid public key string returns InvalidData with details containing `"Invalid age public key"` |
| `test_read_public_key_empty_file`           | Reading a public key from an empty file returns InvalidData with details containing `"empty"`               |
| `test_write_and_read_encrypted_private_key` | Writing encrypted private key bytes and reading them back produces the same bytes                           |
| `test_write_encrypted_private_key_empty`    | Writing empty encrypted key data returns InvalidData                                                        |

### config_tests (6 tests)

| Test name                                      | What it verifies                                                                                                |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `test_keyring_new_creates_directory`           | `KeyringPath::new` creates the `private/` and `public/` subdirectories                                          |
| `test_keyring_open_existing_fails_for_missing` | `KeyringPath::open_existing` returns an error containing `"not found"` for a nonexistent directory              |
| `test_keyring_new_empty_path`                  | `KeyringPath::new` returns an error containing `"empty"` for an empty path string                               |
| `test_save_and_load_metadata`                  | Saving default metadata and loading it back produces an empty identity list                                     |
| `test_load_missing_file`                       | `ConfigLoader::load` returns an Io error for a nonexistent metadata file                                        |
| `test_fingerprint_paths`                       | `fingerprint_private_path` and `fingerprint_public_path` produce paths ending in `.age` and `.pub` respectively |

### crypto_tests (18 tests)

| Test name                                    | What it verifies                                                                                 |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `test_keygen_success`                        | `generate_keypair` returns non-empty public and secret keys                                      |
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
| `test_read_recipients_from_file_invalid_key` | rejects a line that does not start with `"age"`                                                  |
| `test_read_recipients_from_file_empty`       | rejects a file with only comments, returning InvalidData about no valid recipient                |

### error_tests (19 tests)

Every test constructs an error variant, formats it with Display, and asserts
that the formatted string contains the relevant field values. Additional tests
verify Debug output richness, the Result type alias behavior, and manual
`std::io::Error` conversion.

### types_tests (14 tests)

| Test name                              | What it verifies                                              |
| -------------------------------------- | ------------------------------------------------------------- |
| `test_fingerprint_valid_hex`           | Fingerprint::new accepts valid hex strings                    |
| `test_fingerprint_invalid_non_hex`     | Fingerprint::new rejects non-hex characters                   |
| `test_fingerprint_invalid_empty`       | Fingerprint::new rejects empty strings                        |
| `test_fingerprint_equality`            | Two Fingerprints with the same hex are equal                  |
| `test_fingerprint_serde`               | Fingerprint survives JSON serialization round-trip            |
| `test_user_id_trims_whitespace`        | UserID::new trims whitespace from name and email              |
| `test_validate_user_name_valid`        | validate_user_name accepts valid names including apostrophes  |
| `test_validate_user_name_empty`        | validate_user_name rejects empty names                        |
| `test_validate_user_name_too_short`    | validate_user_name rejects single-character names             |
| `test_validate_user_name_invalid_char` | validate_user_name rejects names with invalid characters      |
| `test_validate_user_email_valid`       | validate_user_email accepts valid emails including plus signs |
| `test_validate_user_email_empty`       | validate_user_email rejects empty emails                      |
| `test_validate_user_email_no_at`       | validate_user_email rejects emails without @                  |
| `test_validate_user_email_multiple_at` | validate_user_email rejects emails with more than one @       |

Run the test suite:

```bash
cargo test
```

---

## Placeholder Modules

The following modules are declared and compile successfully but contain no
implementation. They exist to establish the public module tree and will be
populated in future releases.

- **core::output::ascii** -- Will format keyring and identity information as
  human-readable ASCII text.
- **core::output::json** -- Will format keyring and identity information as
  structured JSON output.
- **core::output::toml** -- Will format keyring and identity information as
  TOML, suitable for configuration files.

---

## Build and Lint

The project includes a Makefile with the following targets:

| Target      | Command                                                    | Description                                                         |
| ----------- | ---------------------------------------------------------- | ------------------------------------------------------------------- |
| `fmt`       | `cargo fmt --all`                                          | Auto-format all source files                                        |
| `fmt-check` | `cargo fmt --all -- --check`                               | Check formatting without modifying files                            |
| `clippy`    | `cargo clippy --all-targets --all-features -- -D warnings` | Run Clippy on all targets and features, treating warnings as errors |
| `lint`      | `fmt` then `clippy`                                        | Run both formatting check and Clippy                                |
| `ci`        | `fmt-check` then `clippy` then `cargo test --workspace`    | Full CI pipeline                                                    |
| `test`      | `cargo test --workspace`                                   | Run the full test suite                                             |

The `clippy` target in v0.2.0 runs with `--all-targets --all-features`, which
is stricter than the v0.1.0 target that ran bare `cargo clippy`. This ensures
that Clippy checks test code, dev-dependencies, and all feature flag
combinations.

---

## Security Considerations

- **Secret key zeroization.** The `KeyGenData::secret_key` field is wrapped in
  `Zeroizing<String>`. When the `KeyGenData` value goes out of scope, the
  secret key memory is overwritten with zeroes. Similarly,
  `read_encrypted_private_key` returns `Zeroizing<Vec<u8>>` so that the
  private key bytes are zeroed on drop. However, this only protects against
  reads of deallocated memory. While the values are live, the key material
  exists in plain text on the heap. Applications should minimize the lifetime
  of these values and avoid cloning them unnecessarily.

- **Atomic metadata writes.** `ConfigLoader::save` writes metadata to a
  temporary file in the same directory and then atomically renames it to the
  target path. On POSIX systems, this is an atomic rename operation. On
  Windows, it is an atomic replace. This prevents metadata corruption if the
  process crashes or the machine loses power during a write.

- **Metadata size limit.** `ConfigLoader::load` enforces a 5 MiB limit on the
  metadata file size. This prevents unbounded memory allocation when reading
  untrusted or corrupted files.

- **Public key structural validation.** Public keys written to or read from
  disk are validated by parsing them as `age::x25519::Recipient`. This ensures
  that only structurally valid age public keys are stored in the keyring. It
  does not verify that the key holder actually possesses the corresponding
  secret key.

- **Passphrase minimum length.** The library enforces a minimum passphrase
  length of 8 characters before calling librage. This is a defense against
  trivially weak passphrases but is not a substitute for proper passphrase
  strength validation or key derivation best practices.

- **No constant-time operations.** age-credentials does not perform
  constant-time comparison on fingerprints, user IDs, or ciphertext. This is
  acceptable because these values are not secrets in the cryptographic sense
  (fingerprints are public identifiers, and ciphertext is intended to be
  transmitted). However, applications should not use this library's comparison
  logic for secret values such as passphrases.

- **Underlying backend.** All cryptographic security depends on the
  correctness and soundness of librage and the rage implementation.
  age-credentials is a wrapper and does not implement any cryptographic
  primitives itself.

- **Email and name validation is not comprehensive.** Name validation allows
  a specific set of characters. Email validation checks structural properties
  but does not validate RFC 5322 full conformance, domain existence, or MX
  records. Applications that require stricter validation should layer their own
  on top.

- **Keyring directory permissions.** `KeyringPath::new` creates directories
  with default permissions. It does not set restrictive permissions (such as 0700) on the private key directory. On multi-user systems, applications
  should set appropriate permissions after calling `KeyringPath::new`.

---

## Migration from v0.1.0

### Name validation is stricter

Any code that constructed `UserID` values with names shorter than 2 characters,
longer than 255 characters, or containing characters outside the allowed set
(alphabetic, numeric, space, hyphen, apostrophe, period) will now fail at
runtime with `InvalidUserId`.

**Before (v0.1.0):** `UserID::new("A", "a@b.com")` succeeded.

**After (v0.2.0):** `UserID::new("A", "a@b.com")` returns
`Err(AgeCredentialsError::InvalidUserId { reason: "Name too short: 1 chars, minimum 2" })`.

### Email validation is stricter

Any code that constructed `UserID` values with emails longer than 254
characters, containing zero or more than one `@`, having an empty local part
or domain, or containing characters outside the allowed set (alphanumeric,
period, hyphen, underscore, at, plus) will now fail at runtime with
`InvalidUserId`.

**Before (v0.1.0):** `UserID::new("Bob", "a@b@c.com")` succeeded.

**After (v0.2.0):** `UserID::new("Bob", "a@b@c.com")` returns
`Err(AgeCredentialsError::InvalidUserId { reason: "Email must contain exactly one '@'" })`.

### Whitespace is trimmed

Names and emails are now trimmed before storage. If your application relied on
preserving leading or trailing whitespace in these fields, it will no longer do
so.

**Before (v0.1.0):** `UserID::new("  Alice  ", "  a@b.com  ")` stored
`name = "  Alice  "` and `email = "  a@b.com  "`.

**After (v0.2.0):** `UserID::new("  Alice  ", "  a@b.com  ")` stores
`name = "Alice"` and `email = "a@b.com"`.

### Removed modules

The modules `core::api::user_email` and `core::api::user_name` no longer
exist. Replace any imports with the standalone validation functions:

```rust
// Before (v0.1.0): these modules existed but were placeholders with no API
use age_credentials::core::api::user_email;
use age_credentials::core::api::user_name;

// After (v0.2.0): use the standalone validation functions
use age_credentials::{validate_user_name, validate_user_email};

validate_user_name("Alice")?;
validate_user_email("alice@example.com")?;
```

### New dependencies

Your project will now transitively depend on the `age` crate (v0.12.1) and
`tempfile` (v3.27.0) at runtime. If you have a Cargo.lock file, run
`cargo update` to resolve the new dependencies.

---

## Roadmap

The following capabilities are planned for future releases. This list is not
binding and may change.

- Output formatters: ASCII, JSON, TOML (core::output sub-modules).
- Keyring operations: add identity, remove identity, set default identity,
  list identities.
- Duplicate fingerprint detection in ConfigLoader::save.
- Configurable passphrase policies (minimum length, complexity rules).
- Configurable metadata size limit (instead of hard-coded 5 MiB).
- Keyring directory permission enforcement (0700 for private/).
- SSH key recipient support.
- Identity file encryption and decryption (encrypting the metadata or keyring
  itself with a master key).
- Full keyring lifecycle integration test (create keyring, generate identity,
  encrypt, decrypt, rotate, remove).
- crates.io publication.
- Documentation and examples directory.

---

## License

This project is licensed under the MIT License. See the LICENSE file in the
repository for the full text.
