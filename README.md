# age-credentials

Identity and credential management built on the age encryption format.

age-credentials is a Rust library that provides GnuPG-like identity management --
user IDs, keyrings, passphrase protection, configuration persistence, structured
metadata, and multiple output serialization formats -- on top of the simplicity
and security of the age encryption specification. It is designed for developers
who need programmatic control over age identities and credentials without
depending on a CLI tool or the GnuPG runtime.

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
- [Output Formatting](#output-formatting)
  - [Hex Encoding and Decoding](#hex-encoding-and-decoding)
  - [JSON Serialization](#json-serialization)
  - [TOML Serialization](#toml-serialization)
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
  - [Downcasting Serialization Errors](#downcasting-serialization-errors)
- [Module Reference](#module-reference)
- [Testing](#testing)
- [Build and Lint](#build-and-lint)
- [Security Considerations](#security-considerations)
- [Migration from v0.2.0](#migration-from-v020)
- [Migration from v0.1.0](#migration-from-v010)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

age-credentials sits on top of two complementary crates:

- [librage](https://crates.io/crates/librage) (v1.1.0) -- A safe Rust wrapper
  around the [rage](https://str4d.dev/rage) implementation of the
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
- Output formatters for hexadecimal encoding, JSON serialization, and TOML
  serialization.

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
    output/            Output formatting
      mod.rs              Declares and re-exports ascii, json, toml
      ascii.rs            Hex encoding and decoding
      json.rs             JSON serialization and deserialization helpers
      toml.rs             TOML serialization and deserialization helpers
  handler/            Shared infrastructure
    mod.rs              Declares and re-exports error and types
    error.rs            AgeCredentialsError enum and Result alias
    types.rs            Core data types and validation functions
```

All modules are fully implemented. There are no placeholder modules in this
release.

---

## Installation

Install With Cargo

```sh
cargo add age-credentials
```

Install Whit Git

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

| Crate              | Version            | Role                                                            |
| ------------------ | ------------------ | --------------------------------------------------------------- |
| librage            | 1.1.0              | Delegates all age encrypt/decrypt/keygen operations             |
| age                | 0.12.1             | Parses and validates age x25519 recipient public keys           |
| thiserror          | 2.0                | Provides the Error derive macro for AgeCredentialsError         |
| serde              | 1 (derive feature) | Serialization framework for types and metadata                  |
| serde_json         | 1                  | JSON serialization and deserialization for metadata persistence |
| zeroize            | 1 (serde feature)  | Secure zeroing of secret key and private key memory on drop     |
| dirs               | 6                  | Resolves platform-specific config and data directories          |
| sha2               | 0.11               | SHA-2 hashing for fingerprint computation                       |
| eyre               | 0.6.12             | Ergonomic error reporting                                       |
| color-eyre         | 0.6.5              | Colored terminal error reports                                  |
| tracing            | 0.1.44             | Structured log emission                                         |
| tracing-subscriber | 0.3.23             | Configures the tracing subscriber                               |
| tempfile           | 3.27.0             | Atomic file writes in ConfigLoader::save via NamedTempFile      |
| toml               | 1.1.4              | TOML serialization and deserialization (TOML spec 1.1.0)        |

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
let keyring = KeyringPath::new("/home/user/.age-credentials/keyring")
    .expect("keyring init failed");

// Save metadata atomically
let meta = age_credentials::handler::types::Metadata::default();
ConfigLoader::save(keyring.metadata_file(), &meta).expect("save failed");

// Hex encode a fingerprint
use age_credentials::hex_encode;
let hex = hex_encode(b"\x0a\x4d");
assert_eq!(hex, "0a4d");

// Serialize metadata to JSON
use age_credentials::to_json_pretty;
let json = to_json_pretty(&meta).expect("json failed");

// Serialize metadata to TOML
use age_credentials::to_toml_pretty;
let toml_str = to_toml_pretty(&meta).expect("toml failed");
```

---

## Configuration

The `config` module provides two components: `ConfigLoader` for persisting and
reading metadata, and `KeyringPath` for managing the keyring directory layout.
Both are re-exported at the crate root.

### ConfigLoader

```rust
use age_credentials::ConfigLoader;
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

1. Reads the entire file into a string using `std::fs::read_to_string`. If the
   file cannot be read, returns `Err(AgeCredentialsError::Io)`.
2. Checks the size against `MAX_METADATA_SIZE` (5 MiB = 5,242,880 bytes). If
   exceeded, returns `Err(AgeCredentialsError::InvalidData)` with context
   `"metadata file"` and details including actual and maximum sizes.
3. Deserializes the string as JSON into a `Metadata` value. If malformed,
   returns `Err(AgeCredentialsError::Serialization)` with target `"metadata"`
   and the boxed `serde_json::Error`.

#### ConfigLoader::save

```rust
pub fn save(path: impl AsRef<Path>, metadata: &Metadata) -> Result<()>
```

Serializes a `Metadata` value to pretty-printed JSON and writes it atomically
to the target path.

1. Serializes to pretty-printed JSON via `serde_json::to_string_pretty`.
2. Determines the parent directory. If the path has no parent, returns
   `Err(AgeCredentialsError::Config)`.
3. Creates a `tempfile::NamedTempFile` in the parent directory.
4. Writes the JSON bytes to the temporary file.
5. Persists the temporary file to the target path using atomic rename.

Atomic writes prevent metadata corruption on crash or power loss: the metadata
file is always either the old version or the new version, never a partial
write.

### KeyringPath

```rust
use age_credentials::KeyringPath;
```

`KeyringPath` manages the directory layout of a keyring on disk. It holds the
absolute path to the keyring root in a private `root: PathBuf` field.

#### KeyringPath::new

```rust
pub fn new(path: impl AsRef<Path>) -> Result<Self>
```

Creates a new keyring at the given path. Creates the root directory, resolves
to an absolute path via `canonicalize`, then creates `private/` and `public/`
subdirectories. Rejects empty paths. After calling `new`, the following
directory structure exists:

```
{path}/
  private/
  public/
```

#### KeyringPath::open_existing

```rust
pub fn open_existing(path: impl AsRef<Path>) -> Result<Self>
```

Opens an existing keyring directory without creating any directories. Returns
`Err(AgeCredentialsError::Config)` if the path is not a directory.

#### KeyringPath accessor methods

```rust
pub fn metadata_file(&self) -> PathBuf              // {root}/metadata.json
pub fn private_dir(&self) -> PathBuf                 // {root}/private
pub fn public_dir(&self) -> PathBuf                  // {root}/public
pub fn fingerprint_private_path(&self, fp: &str) -> PathBuf  // {root}/private/{fp}.age
pub fn fingerprint_public_path(&self, fp: &str) -> PathBuf   // {root}/public/{fp}.pub
```

---

## Cryptography

All cryptographic functions live under `age_credentials::core::crypto` and are
re-exported through the `core` module and at the crate root.

### Key Generation

```rust
pub fn generate_keypair() -> Result<KeyGenData>
```

Generates a new age key pair via `librage::generate_keypair`. Returns
`KeyGenData` with `public_key: String` (starts with `age1`) and
`secret_key: Zeroizing<String>` (memory overwritten with zeroes on drop).

### Encryption

```rust
pub fn encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>>
pub fn encrypt_multiple(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>>
```

Encrypts plaintext to one or more public keys. Validates non-empty keys and
non-empty recipient lists before calling librage. Returns ciphertext as
`Vec<u8>`.

### Decryption

```rust
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>>
```

Decrypts ciphertext using a secret key. Handles both binary and armored
ciphertext transparently. Validates non-empty secret key.

### Multi-Recipient Encryption

Produces a single ciphertext decryptable by any of the corresponding secret
keys:

```rust
let ciphertext = encrypt_multiple(b"shared", &[&kp1.public_key, &kp2.public_key])?;
let dec1 = decrypt(&ciphertext, &kp1.secret_key)?;
let dec2 = decrypt(&ciphertext, &kp2.secret_key)?;
assert_eq!(dec1, dec2);
```

### Armored Encryption

```rust
pub fn encrypt_armored(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>>
pub fn encrypt_multiple_armored(plaintext: &[u8], public_keys: &[&str]) -> Result<Vec<u8>>
```

Same as `encrypt` / `encrypt_multiple` but with ASCII-armored output beginning
with `-----BEGIN AGE ENCRYPTED FILE-----`. Decrypted using the same `decrypt`
function.

### Passphrase Encryption

```rust
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>>
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>>
```

Encrypts and decrypts using a passphrase. Enforces a minimum passphrase length
of 8 characters before calling librage. Returns
`Err(AgeCredentialsError::PassphraseTooShort)` for shorter passphrases.

### Recipient Files

```rust
pub fn read_recipients_from_file(path: impl AsRef<Path>) -> Result<Vec<String>>
```

Reads a recipient list from a text file. Lines starting with `#` are comments.
Blank lines are skipped. Every non-comment, non-blank line must start with
`age`. Returns the list of trimmed recipient strings.

---

## Key Management API

The `core::api` module provides I/O operations for reading and writing key
files. Re-exported through `core` and at the crate root.

### Public Key Operations

```rust
pub fn read_public_key(path: impl AsRef<Path>) -> Result<String>
pub fn write_public_key(path: impl AsRef<Path>, public_key: &str) -> Result<()>
```

`read_public_key` reads a file, trims whitespace, and validates the content as
an age x25519 recipient. `write_public_key` validates the key string first,
then writes it with a trailing newline. Invalid keys are never written to
disk.

### Private Key Operations

```rust
pub fn read_encrypted_private_key(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>>
pub fn write_encrypted_private_key(path: impl AsRef<Path>, encrypted_key: &[u8]) -> Result<()>
```

`read_encrypted_private_key` reads raw bytes and returns them wrapped in
`Zeroizing<Vec<u8>>` (zeroed on drop). `write_encrypted_private_key` validates
that the data is non-empty before writing.

### Public Key Validation

Internal function `validate_public_key_string` checks that the key is non-empty
and parses successfully as `age::x25519::Recipient`. The `age` crate's parser
validates the `age1` prefix and full Bech32 encoding of the x25519 public key.

---

## Output Formatting

The `core::output` module provides serialization and encoding utilities for
converting library types to text formats. All three sub-modules are re-exported
at the crate root.

```rust
use age_credentials::{
    hex_encode, hex_decode,
    to_json_pretty, from_json,
    to_toml_pretty, from_toml,
};
```

### Hex Encoding and Decoding

#### hex_encode

```rust
pub fn hex_encode(data: &[u8]) -> String
```

Encodes a byte slice to a lowercase hexadecimal string. Each input byte
produces exactly two hex digits using the format `{:02x}`. The output string
has length `data.len() * 2`. The function pre-allocates the exact required
capacity and cannot fail.

**Algorithm:** Iterates over each byte, formatting it as a two-digit lowercase
hex value and writing it into a pre-allocated `String` using
`std::fmt::Write`. This avoids allocating intermediate strings per byte.

**Examples:**

```rust
use age_credentials::hex_encode;

assert_eq!(hex_encode(&[0x00, 0xff, 0x80, 0x63]), "00ff8063");
assert_eq!(hex_encode(&[]), "");
assert_eq!(hex_encode(&[0x0a, 0x4d]), "0a4d");
```

#### hex_decode

```rust
pub fn hex_decode(hex: &str) -> Result<Vec<u8>>
```

Decodes a hexadecimal string to a byte vector. Leading and trailing whitespace
is trimmed before processing.

**Validation and error reporting:**

| Condition                                    | Error                                                                                           |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Trimmed input is empty                       | `InvalidData { context: "hex decode", details: "Input string is empty" }`                       |
| Trimmed input length is odd                  | `InvalidData { context: "hex decode", details: "Input length {n} is odd, must be even" }`       |
| Character at position `p` is not a hex digit | `InvalidData { context: "hex decode", details: "Invalid hex character '{c}' at position {p}" }` |

Position indices in error messages are 0-based byte positions in the trimmed
input string.

**Accepted characters:** `0-9`, `a-f`, `A-F`. All other characters produce an
`InvalidData` error with the character and its position.

**Algorithm:**

1. Trim whitespace.
2. Validate non-empty and even length.
3. Iterate over the trimmed input in 2-byte chunks.
4. Convert each chunk to a byte: high nibble (`chunk[0]`) shifted left by 4,
   OR'd with low nibble (`chunk[1]`).
5. Return the assembled byte vector.

**Round-trip guarantee:** For any byte slice `data`, `hex_decode(&hex_encode(data))`
returns `Ok(data)`.

**Examples:**

```rust
use age_credentials::{hex_encode, hex_decode};

let data = vec![0x00, 0xff, 0x80, 0x63];
let encoded = hex_encode(&data);
let decoded = hex_decode(&encoded)?;
assert_eq!(decoded, data);

// Whitespace is trimmed
let decoded = hex_decode("  00ff  ")?;
assert_eq!(decoded, vec![0x00, 0xff]);

// Error: odd length
let err = hex_decode("abc").unwrap_err();

// Error: invalid character
let err = hex_decode("abz0").unwrap_err();
```

### JSON Serialization

#### to_json_pretty

```rust
pub fn to_json_pretty<T: Serialize>(value: &T) -> Result<String>
```

Serializes any type implementing `serde::Serialize` to a pretty-printed JSON
string using `serde_json::to_string_pretty`. On failure, returns
`Err(AgeCredentialsError::Serialization)` with:

- `target: "json"`
- `path: PathBuf::from("<memory>")` -- indicates this is an in-memory
  operation, not associated with a filesystem path.
- `source: Box<serde_json::Error>` -- the underlying serialization error.

The `<memory>` path sentinel distinguishes errors from these helper functions
(performed in memory) from errors in `ConfigLoader::load` / `ConfigLoader::save`
(performed on files and carrying actual file paths).

**Example:**

```rust
use age_credentials::{Metadata, to_json_pretty};

let meta = Metadata::default();
let json = to_json_pretty(&meta)?;
// json is a pretty-printed JSON string
```

#### from_json

```rust
pub fn from_json<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T>
```

Deserializes a JSON string into any type implementing `serde::Deserialize`. On
failure, returns `Err(AgeCredentialsError::Serialization)` with the same
conventions as `to_json_pretty`.

The `for<'de> Deserialize<'de>` bound is required because the deserializer
borrows from the input string. This is the standard bound for
`serde_json::from_str`.

**Example:**

```rust
use age_credentials::{Metadata, to_json_pretty, from_json};

let meta = Metadata::default();
let json = to_json_pretty(&meta)?;
let meta2: Metadata = from_json(&json)?;
assert_eq!(meta.identities, meta2.identities);
```

### TOML Serialization

#### to_toml_pretty

```rust
pub fn to_toml_pretty<T: Serialize>(value: &T) -> Result<String>
```

Serializes any type implementing `serde::Serialize` to a pretty-printed TOML
string using `toml::to_string_pretty`. The `toml` crate version 1.1.4
implements TOML spec 1.1.0. On failure, returns
`Err(AgeCredentialsError::Serialization)` with:

- `target: "toml"`
- `path: PathBuf::from("<memory>")`
- `source: Box<toml::ser::Error>` -- the underlying TOML serialization error.

**TOML type limitations:** Not all Rust types have a TOML representation. Types
that cannot be represented in TOML include:

- Byte arrays (`Vec<u8>`, `[u8; N]`).
- Tuple types other than two-element tuples (which map to TOML arrays).
- Map types with non-string keys.
- Enum variants (unless using custom serialization).

If you attempt to serialize a type with no TOML representation, the function
returns a `Serialization` error.

**Example:**

```rust
use age_credentials::{Metadata, to_toml_pretty};

let meta = Metadata::default();
let toml_str = to_toml_pretty(&meta)?;
// toml_str is a pretty-printed TOML string
```

#### from_toml

```rust
pub fn from_toml<T: for<'de> Deserialize<'de>>(toml_str: &str) -> Result<T>
```

Deserializes a TOML string into any type implementing `serde::Deserialize`. On
failure, returns `Err(AgeCredentialsError::Serialization)` with the same
conventions as `to_toml_pretty`, except the source is
`Box<toml::de::Error>`.

**Example:**

```rust
use age_credentials::{Metadata, to_toml_pretty, from_toml};

let meta = Metadata::default();
let toml_str = to_toml_pretty(&meta)?;
let meta2: Metadata = from_toml(&toml_str)?;
assert_eq!(meta.identities, meta2.identities);
```

---

## Type System

All types live under `age_credentials::handler::types` and are re-exported at
the crate root.

### Fingerprint

```rust
pub struct Fingerprint(String);
```

A validated hexadecimal string. Constructed via `Fingerprint::new(hex)` which
rejects empty strings and non-hex-digit characters. Implements `Debug`, `Clone`,
`PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`, and `Display` (yields
the bare hex string).

### UserID

```rust
pub struct UserID {
    pub name: String,
    pub email: String,
}
```

A validated user identity. Constructed via `UserID::new(name, email)` which
trims whitespace, validates the name (minimum 2 characters, maximum 255,
allowed characters only), and validates the email (exactly one `@`, maximum
254 characters, allowed characters only). The `to_formatted` method returns
`"Name <email>"`.

### Name Validation

```rust
pub fn validate_user_name(name: &str) -> Result<(), AgeCredentialsError>
```

Validates a name without constructing a `UserID`. Rules applied to the trimmed
value:

1. Not empty.
2. At least 2 characters.
3. At most 255 characters.
4. Only alphabetic, numeric, space, hyphen, apostrophe, or period characters.

### Email Validation

```rust
pub fn validate_user_email(email: &str) -> Result<(), AgeCredentialsError>
```

Validates an email without constructing a `UserID`. Rules applied to the trimmed
value:

1. Not empty.
2. At most 254 characters (RFC 5321).
3. Exactly one `@` character.
4. Non-empty local part and domain.
5. Only alphanumeric, period, hyphen, underscore, `@`, or plus characters.

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

A full identity record. No constructor; use struct literal syntax. Implements
`Debug`, `Clone`, `Serialize`, `Deserialize`.

### Metadata

```rust
pub struct Metadata {
    pub identities: Vec<Identity>,
    pub default_identity: Option<Fingerprint>,
}
```

The top-level metadata structure. Implements `Default` (empty identity list, no
default), `Debug`, `Clone`, `Serialize`, `Deserialize`. This is the unit of
persistence for `ConfigLoader`.

### KeyGenData

```rust
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
```

The return type of `generate_keypair`. `secret_key` is wrapped in
`Zeroizing<String>` and overwritten with zeroes on drop. Implements `Debug` and
`Clone`. Does not implement `Serialize` or `Deserialize` to prevent accidental
serialization of the secret key.

---

## Error Handling

All fallible operations return `handler::error::Result<T>`, which expands to
`std::result::Result<T, AgeCredentialsError>`.

### Error Variants

| Variant               | Source chain                     | Producing modules                             |
| --------------------- | -------------------------------- | --------------------------------------------- |
| `Io`                  | Yes (`std::io::Error`)           | config, core::api, core::crypto               |
| `Serialization`       | Yes (`Box<dyn Error+Send+Sync>`) | config, core::output                          |
| `DuplicateIdentity`   | No                               | (reserved)                                    |
| `IdentityNotFound`    | No                               | (reserved)                                    |
| `InvalidEmail`        | No                               | (reserved)                                    |
| `InvalidName`         | No                               | (reserved)                                    |
| `PassphraseIncorrect` | No                               | (reserved)                                    |
| `EncryptionFailed`    | No                               | core::crypto                                  |
| `DecryptionFailed`    | No                               | core::crypto                                  |
| `KeyGenFailed`        | No                               | core::crypto                                  |
| `MetadataNotFound`    | No                               | (reserved)                                    |
| `InvalidData`         | No                               | core::crypto, core::api, config, core::output |
| `Config`              | No                               | config                                        |
| `PassphraseTooShort`  | No                               | core::crypto                                  |
| `InvalidFingerprint`  | No                               | handler::types                                |
| `InvalidUserId`       | No                               | handler::types                                |

### Result Type Alias

```rust
pub type Result<T> = std::result::Result<T, AgeCredentialsError>;
```

Exported at the crate root. Use `?` to propagate errors in any function that
returns `Result<T>`.

### Pattern Matching Errors

```rust
match encrypt(b"data", "") {
    Ok(_) => println!("Encrypted"),
    Err(AgeCredentialsError::InvalidData { context, details }) => {
        eprintln!("Validation error in {}: {}", context, details);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### Downcasting Serialization Errors

Because the `Serialization` variant uses `Box<dyn std::error::Error + Send + Sync>`,
you can downcast the source to the concrete error type:

```rust
if let AgeCredentialsError::Serialization { target, source, .. } = &err {
    match *target {
        "metadata" | "json" => {
            if let Some(json_err) = source.downcast_ref::<serde_json::Error>() {
                eprintln!("JSON error: {}", json_err);
            }
        }
        "toml" => {
            if let Some(toml_err) = source.downcast_ref::<toml::de::Error>() {
                eprintln!("TOML decode error: {}", toml_err);
            } else if let Some(toml_err) = source.downcast_ref::<toml::ser::Error>() {
                eprintln!("TOML encode error: {}", toml_err);
            }
        }
        _ => eprintln!("Unknown serialization error: {}", source),
    }
}
```

---

## Module Reference

| Module path               | Status      | Description                                                                                                         |
| ------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------- |
| `config`                  | Implemented | Top-level configuration module                                                                                      |
| `config::loader`          | Implemented | `ConfigLoader::load` and `ConfigLoader::save` for metadata JSON persistence with atomic writes and 5 MiB size limit |
| `config::path`            | Implemented | `KeyringPath` for keyring directory layout management                                                               |
| `core`                    | Implemented | Top-level core module                                                                                               |
| `core::api`               | Implemented | Key management I/O                                                                                                  |
| `core::api::private_keys` | Implemented | Read/write encrypted private key files with zeroized buffers                                                        |
| `core::api::public_keys`  | Implemented | Read/write public key files with `age::x25519::Recipient` validation                                                |
| `core::crypto`            | Implemented | All cryptographic operations (encrypt, decrypt, keygen, armor, passphrase, recipient)                               |
| `core::output`            | Implemented | Output formatting                                                                                                   |
| `core::output::ascii`     | Implemented | `hex_encode` and `hex_decode` for hexadecimal encoding and decoding                                                 |
| `core::output::json`      | Implemented | `to_json_pretty` and `from_json` for JSON serialization helpers                                                     |
| `core::output::toml`      | Implemented | `to_toml_pretty` and `from_toml` for TOML serialization helpers                                                     |
| `handler`                 | Implemented | Shared infrastructure                                                                                               |
| `handler::error`          | Implemented | `AgeCredentialsError` enum and `Result` alias                                                                       |
| `handler::types`          | Implemented | Core data types and validation functions                                                                            |

---

## Testing

The test suite contains 70 tests across 6 files.

### api_tests (5 tests)

| Test                                        | What it verifies                                  |
| ------------------------------------------- | ------------------------------------------------- |
| `test_write_and_read_public_key`            | Write and read round-trip produces the same key   |
| `test_write_public_key_invalid`             | Invalid key string returns InvalidData            |
| `test_read_public_key_empty_file`           | Empty file returns InvalidData                    |
| `test_write_and_read_encrypted_private_key` | Write and read round-trip produces the same bytes |
| `test_write_encrypted_private_key_empty`    | Empty key data returns InvalidData                |

### config_tests (6 tests)

| Test                                           | What it verifies                                    |
| ---------------------------------------------- | --------------------------------------------------- |
| `test_keyring_new_creates_directory`           | `KeyringPath::new` creates private/ and public/     |
| `test_keyring_open_existing_fails_for_missing` | Nonexistent directory returns Config error          |
| `test_keyring_new_empty_path`                  | Empty path returns Config error                     |
| `test_save_and_load_metadata`                  | Save and load round-trip preserves default metadata |
| `test_load_missing_file`                       | Missing file returns Io error                       |
| `test_fingerprint_paths`                       | Fingerprint paths end with `.age` and `.pub`        |

### crypto_tests (18 tests)

Key generation, single and multi-recipient encrypt/decrypt roundtrips, armored
encrypt/decrypt, passphrase encrypt/decrypt, empty and invalid key rejection,
wrong-key and wrong-passphrase errors, recipient file parsing.

### error_tests (19 tests)

Display output of every error variant, Debug output richness, Result type alias,
manual io::Error conversion, boxed Serialization error construction.

### output_tests (8 tests)

| Test                               | What it verifies                                                   |
| ---------------------------------- | ------------------------------------------------------------------ |
| `test_hex_encode_decode_roundtrip` | `hex_decode(hex_encode(data))` returns `data`                      |
| `test_hex_decode_empty`            | Empty input returns InvalidData                                    |
| `test_hex_decode_odd_length`       | Odd-length input returns InvalidData with "odd"                    |
| `test_hex_decode_invalid_char`     | Non-hex character returns InvalidData with "Invalid hex character" |
| `test_json_roundtrip`              | `from_json(to_json_pretty(obj))` returns equal object              |
| `test_from_json_invalid`           | Invalid JSON returns Serialization error                           |
| `test_toml_roundtrip`              | `from_toml(to_toml_pretty(obj))` returns equal object              |
| `test_from_toml_invalid`           | Invalid TOML returns Serialization error                           |

### types_tests (14 tests)

Fingerprint creation, validation, and serialization. UserID whitespace trimming.
Name and email validation (valid, empty, too short, invalid character, no `@`,
multiple `@`).

Run the test suite:

```bash
cargo test
```

---

## Build and Lint

The project includes a Makefile with the following targets:

| Target      | Command                                                    | Description                                                |
| ----------- | ---------------------------------------------------------- | ---------------------------------------------------------- |
| `fmt`       | `cargo fmt --all`                                          | Auto-format all source files                               |
| `fmt-check` | `cargo fmt --all -- --check`                               | Check formatting without modifying files                   |
| `clippy`    | `cargo clippy --all-targets --all-features -- -D warnings` | Run Clippy on all targets and features, warnings as errors |
| `lint`      | `fmt` then `clippy`                                        | Run both formatting check and Clippy                       |
| `ci`        | `fmt-check` then `clippy` then `cargo test --workspace`    | Full CI pipeline                                           |
| `test`      | `cargo test --workspace`                                   | Run the full test suite                                    |

---

## Security Considerations

- **Secret key zeroization.** `KeyGenData::secret_key` and the return value of
  `read_encrypted_private_key` use `Zeroizing` wrappers. Memory is overwritten
  with zeroes on drop. While the values are live, the key material exists in
  plain text on the heap. Minimize lifetimes and avoid unnecessary clones.

- **Atomic metadata writes.** `ConfigLoader::save` uses `NamedTempFile` and
  atomic rename. Prevents corruption on crash or power loss.

- **Metadata size limit.** `ConfigLoader::load` enforces a 5 MiB limit.
  Prevents unbounded memory allocation from untrusted files.

- **Public key structural validation.** Public keys are validated by parsing as
  `age::x25519::Recipient`. Does not verify key holder identity.

- **Passphrase minimum length.** 8 characters enforced before calling librage.
  Not a substitute for passphrase strength validation.

- **No constant-time operations.** Fingerprints, user IDs, and ciphertext are
  compared using standard Rust equality. Do not use for secret values.

- **Hex decode operates on bytes.** `hex_decode` processes its input as raw
  bytes via `as_bytes().chunks(2)`. It does not interpret multi-byte UTF-8
  sequences. In practice, hex strings are ASCII-only.

- **Underlying backend.** All cryptographic security depends on librage and the
  rage implementation. age-credentials does not implement cryptographic
  primitives.

- **TOML type safety.** `to_toml_pretty` may fail at runtime for types with no
  TOML representation. Validate that your types are TOML-compatible before
  relying on this function in production paths.

- **Keyring directory permissions.** `KeyringPath::new` creates directories with
  default permissions. Set restrictive permissions (0700 for private/) on
  multi-user systems.

---

## Migration from v0.2.0

### Serialization error source type changed

The `AgeCredentialsError::Serialization` variant's `source` field changed from
`serde_json::Error` to `Box<dyn std::error::Error + Send + Sync>`. Code that
accesses the `source` field directly must be updated:

```rust
// Before (v0.2.0):
Err(AgeCredentialsError::Serialization { source, .. }) => {
    let _json_err: &serde_json::Error = &source;
}

// After (v0.3.0):
Err(AgeCredentialsError::Serialization { source, .. }) => {
    if let Some(json_err) = source.downcast_ref::<serde_json::Error>() {
        // handle serde_json error
    }
}
```

If you construct `Serialization` errors manually, wrap the source in `Box::new`:

```rust
// Before:
AgeCredentialsError::Serialization { target: "x", path: p, source: json_err }

// After:
AgeCredentialsError::Serialization { target: "x", path: p, source: Box::new(json_err) }
```

### New dependency: toml

Your project now transitively depends on the `toml` crate (v1.1.4) and its
transitive dependencies (`indexmap`, `winnow`, etc.). Run `cargo update` to
resolve.

### librage source changed

The `librage` dependency is now resolved from crates.io instead of a git
repository. Remove any git-related configuration from your `Cargo.toml` if you
overrode it. The API is unchanged.

---

## Migration from v0.1.0

### Name validation is stricter

Names must be at least 2 characters (after trimming), at most 255 characters,
and contain only alphabetic, numeric, space, hyphen, apostrophe, or period
characters.

### Email validation is stricter

Emails must contain exactly one `@`, have non-empty local part and domain, be
at most 254 characters, and contain only alphanumeric, period, hyphen,
underscore, `@`, or plus characters.

### Whitespace is trimmed

`UserID::new` trims leading and trailing whitespace from both name and email
before storage.

### Removed modules

`core::api::user_email` and `core::api::user_name` no longer exist. Use
`validate_user_name` and `validate_user_email` instead.

### Serialization error is boxed

The `Serialization` variant's `source` field is
`Box<dyn std::error::Error + Send + Sync>` instead of `serde_json::Error`.

---

## Roadmap

- Keyring operations: add identity, remove identity, set default identity,
  list identities.
- Duplicate fingerprint detection in ConfigLoader::save.
- Configurable passphrase policies.
- Configurable metadata size limit.
- Keyring directory permission enforcement (0700 for private/).
- SSH key recipient support.
- Identity file encryption (encrypting the metadata or keyring itself with a
  master key).
- Full keyring lifecycle integration test.
- crates.io publication.
- Examples directory.

---

## License

This project is licensed under the MIT License. See the LICENSE file in the
repository for the full text.
