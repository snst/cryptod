# cryptod - Cryptographic Services Daemon

A Rust daemon that provides cryptographic services over Unix domain sockets, with a C++ client library and an OpenSSL 3.x provider.
The daemon implements a backend-agnostic cryptographic API that abstracts over various backends. The reference implementation uses RustCrypto crates for software-based cryptography.
## 1. Overview

### 1.1 Purpose
The `proto/crypto_api.proto` schema defines the wire-level, backend-agnostic cryptographic API used between clients and the `cryptod` daemon. It provides a unified interface layer that abstracts over various cryptographic backends including software implementations, Hardware Security Modules (HSMs), Trusted Platform Modules (TPMs), PKCS#11 tokens, and secure enclaves.

In the daemon implementation, the protobuf contract is bridged to the Rust backend interface defined in `crates/crypto-api/src/lib.rs`.

### 1.2 Scope
This document covers:
- Architectural design and component organization
- Interface specifications and contracts
- Design patterns and principles employed
- Extension mechanisms and integration points
- Security considerations

### 1.3 Design Philosophy
The API follows an **interface-contract** design pattern, with protocol definitions in protobuf and implementation logic in provider backends. This separation enables:
- Multiple backend implementations
- Testing with mock providers
- Swappable cryptographic engines at runtime
- Provider capability discovery at runtime

### 1.4 Interface Layers Overview

The project has two API layers that must stay aligned:

| Layer | Source | Role |
|------|--------|------|
| **Wire Interface (Client <-> Daemon)** | `proto/crypto_api.proto` | On-the-wire request/response protocol, message schemas, error codes |
| **Backend Interface (Daemon <-> Provider)** | `crates/crypto-api/src/lib.rs` | Rust trait and types used by daemon handlers to execute crypto operations |

The daemon handler layer maps protobuf requests to `CryptoProvider` trait calls and maps `CryptoError` results back to protobuf `CryptoResponse.error`.

---

## 2. Design Goals

| Goal | Description |
|------|-------------|
| **Backend-Agnostic** | Single API supporting software, HSM, TPM, PKCS#11, and enclave backends |
| **Opaque Key Handles** | Support both plaintext key material and opaque hardware-backed handles |
| **Streaming API** | Pattern: `init → update → finish` for memory-efficient large data processing |
| **Zero-Copy Friendly** | Minimize data copying through borrowed references and output buffers |
| **Extensible Algorithms** | Registry pattern allowing new algorithm additions |
| **AEAD Support** | First-class support for authenticated encryption (GCM, CCM) |
| **KDF Support** | Built-in key derivation functions (HKDF, PBKDF2, TLS 1.2 EMS PRF) |
| **Capability Discovery** | Runtime query of provider-supported algorithms |
| **Comprehensive Crypto Primitives** | Hashing, MAC, encryption, signing, key agreement, KDF, RNG |

---

## 3. Architecture Overview

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Application Layer                           │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│          Protobuf Wire Interface (`proto/crypto_api.proto`)         │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│      Daemon Handler Mapping -> `CryptoProvider` (Rust trait)       │
│  ┌──────────────┬──────────────┬──────────────┬──────────────────┐  │
│  │ Key Mgmt     │ Primitives   │ Streaming    │ KDF/Random       │  │
│  │              │ Factories    │ Contexts     │                  │  │
│  └──────────────┴──────────────┴──────────────┴──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
          ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
          │  Software   │  │    HSM      │  │    TPM      │
          │  Backend    │  │   Backend   │  │   Backend   │
          └─────────────┘  └─────────────┘  └─────────────┘
```

### 3.2 Component Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│           proto/crypto_api.proto + crates/crypto-api/src/lib.rs            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────────┐  │
│  │   Error Model    │    │  Algorithm Types │    │    Key Management    │  │
│  │                  │    │                  │    │                      │  │
│  │  • CryptoError   │    │  • HashAlgorithm │    │  • KeyObject trait   │  │
│  │  • CryptoResult  │    │  • CipherMode    │    │  • ImportKeyParams   │  │
│  │  • Error helpers │    │  • SignatureAlg  │    │  • GenerateKeyParams │  │
│  │                  │    │  • KeyAgreement  │    │  • KeyMaterial       │  │
│  │                  │    │  • KdfAlgorithm  │    │  • KeyWrapParams     │  │
│  └──────────────────┘    └──────────────────┘    └──────────────────────┘  │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        CryptoProvider Trait                          │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │  │
│  │  │   hash()   │ │   hmac()   │ │  cipher_*  │ │ signer/verifier()  │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │  │
│  │  ┌────────────────────────┐  ┌─────────────┐  ┌────────────────────┐ │  │
│  │  │    key_agreement()     │  │ derive_key()│  │ capabilities()     │ │  │
│  │  └────────────────────────┘  └─────────────┘  └────────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌─────────────────────────────────┐   │  │
│  │  │ wrap_key() │ │unwrap_key()│ │                                 │   │  │
│  │  └────────────┘ └────────────┘ └─────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                       Streaming Contexts                             │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │  │
│  │  │HashContext │ │MacContext  │ │CipherCtx   │ │Sign/VerifyContext  │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Core Components

### 4.1 Error Model

The system uses two related error models:
- **Backend (Rust):** `CryptoError` enum in `crates/crypto-api/src/lib.rs`
- **Wire (protobuf):** `CryptoError` message + `ErrorCode` enum in `proto/crypto_api.proto`

The daemon maps backend errors to wire error codes.

Wire error categories:

| Error Variant | Description | Context Fields |
|---------------|-------------|----------------|
| `InvalidKey` | Key is malformed, wrong type, or incompatible | `reason: Option<String>` |
| `InvalidAlgorithm` | Requested algorithm not supported | `algorithm: Option<String>` |
| `InvalidState` | Operation called in wrong context state | `reason: Option<String>` |
| `InvalidInput` | Malformed or out-of-range input data | `reason: Option<String>` |
| `InvalidNonce` | Nonce/IV is wrong size or reused | `expected_len`, `actual_len` |
| `TagMismatch` | AEAD authentication tag verification failed | - |
| `DataTooLarge` | Input exceeds algorithm limits | `max_size: Option<usize>` |
| `AuthenticationFailed` | MAC or signature verification failed | - |
| `Unsupported` | Feature not implemented by backend | `feature: Option<String>` |
| `BackendError` | Backend-specific failure | `code`, `message` |
| `EntropyUnavailable` | RNG source unavailable | - |
| `BufferTooSmall` | Output buffer insufficient | `required`, `provided` |
| `KeyNotFound` | Key not found in hardware backend | `key_id: Option<String>` |
| `KeyExpired` | Key has expired or been revoked | - |
| `UsageNotPermitted` | Operation not allowed by key usage flags | `operation: Option<String>` |
| `DeviceError` | Hardware device communication failure | `message: Option<String>` |
| `Timeout` | Operation timed out | - |
| `ContextNotFound` | Streaming context handle is unknown or expired | `context_handle` |

All fallible operations return `CryptoResult<T>` which is aliased to `Result<T, CryptoError>`.

**Error Construction Helpers:**
```rust
CryptoError::invalid_key("RSA key too small")
CryptoError::invalid_algorithm("IDEA")
CryptoError::backend_error("HSM connection lost")
CryptoError::buffer_too_small(32, 16)
```

### 4.2 CryptoProvider Trait

The central abstraction point. All cryptographic operations flow through a provider implementation.

```rust
pub trait CryptoProvider: Send + Sync {
    // Provider info
    fn name(&self) -> &str;
    fn capabilities(&self) -> ProviderCapabilities;
    fn supports_algorithm(&self, algorithm: &KeyAlgorithm) -> bool;

    // Key management
    fn create_key(&self, params: CreateKeyParams) -> CryptoResult<KeyHandle>;
    fn import_key(&self, params: ImportKeyParams) -> CryptoResult<KeyHandle>;
    fn key_info(&self, key: &KeyHandle) -> CryptoResult<KeyInfo>;
    fn find_key(&self, query: KeyQuery) -> CryptoResult<Option<KeyHandle>>;
    fn export_key(&self, key: &KeyHandle, format: KeyFormat) -> CryptoResult<Vec<u8>>;
    fn delete_key(&self, key: &KeyHandle) -> CryptoResult<()>;

    // Factories and KDF
    fn hash(&self, algorithm: HashAlgorithm) -> CryptoResult<Box<dyn HashContext>>;
    fn hmac(&self, algorithm: MacAlgorithm, key: &KeyHandle)
        -> CryptoResult<Box<dyn MacContext>>;
    fn cipher_encrypt(&self, params: CipherParams, key: &KeyHandle)
        -> CryptoResult<Box<dyn CipherContext>>;
    fn cipher_decrypt(&self, params: CipherParams, key: &KeyHandle)
        -> CryptoResult<Box<dyn CipherContext>>;
    fn signer(&self, params: SignatureParams, key: &KeyHandle)
        -> CryptoResult<Box<dyn SignContext>>;
    fn verifier(&self, params: SignatureParams, key: &KeyHandle)
        -> CryptoResult<Box<dyn VerifyContext>>;
    fn key_agreement(&self, params: KeyAgreementParams, private_key: &KeyHandle)
        -> CryptoResult<Box<dyn KeyAgreementContext>>;
    fn random(&self) -> CryptoResult<Box<dyn RandomGenerator>>;
    fn derive_key(&self, params: KdfParams) -> CryptoResult<Vec<u8>>;
}
```

**Key Characteristics:**
- Thread-safe (`Send + Sync`)
- Uses opaque `KeyHandle` for provider-managed key references
- Factory pattern for creating streaming contexts
- Capability discovery for runtime algorithm negotiation

**Capability Discovery:**
```rust
pub struct ProviderCapabilities {
    pub algorithms: Vec<KeyAlgorithm>,
    pub hash_algorithms: Vec<HashAlgorithm>,
    pub cipher_modes: Vec<CipherMode>,
    pub signature_algorithms: Vec<SignatureAlgorithm>,
}
```

### 4.3 Key Management

#### 4.3.1 KeyObject Trait

Abstract representation of cryptographic keys:

```rust
pub trait KeyObject: Debug + Send + Sync {
    fn info(&self) -> &KeyInfo;

    fn algorithm(&self) -> &KeyAlgorithm { ... }
    fn usage(&self) -> KeyUsage { ... }
    fn is_exportable(&self) -> bool { ... }
}
```

#### 4.3.2 KeyUsage Flags

`KeyUsage` in the backend interface is a `bitflags` type (`u8`) with flags
`ENCRYPT`, `DECRYPT`, `SIGN`, `VERIFY`, `DERIVE`, `WRAP`, `UNWRAP`, and `ALL`.

Convenience constants include `ENCRYPT_ONLY`, `DECRYPT_ONLY`, `SIGN_ONLY`,
`VERIFY_ONLY`, `DERIVE_ONLY`, `SYMMETRIC`, and `ASYMMETRIC_SIGN`.

#### 4.3.3 Key Lifecycle

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Generate   │     │    Import    │     │    Export    │
│  create_     │     │  import_     │     │  export_     │
│    key()     │     │    key()     │     │    key()     │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────────┐
│                      KeyObject                           │
│   (Opaque handle or wrapped plaintext material)          │
└──────────────────────────────────────────────────────────┘
       │                    │
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│   wrap_key() │     │ unwrap_key() │
│ (secure exp) │     │ (secure imp) │
└──────────────┘     └──────────────┘
       │
       ▼
┌──────────────┐
│   delete_    │
│    key()     │
└──────────────┘
```

**Key Wrapping (RFC 3394/5649):**
```rust
// Wrap a key for secure transport
let wrapped = provider.wrap_key(&key_to_wrap, &wrapping_key, KeyWrapParams {
    algorithm: KeyWrapAlgorithm::AesKw,
    iv: None,
})?;

// Unwrap a received key
let key = provider.unwrap_key(
    &wrapped,
    &unwrapping_key,
    KeyWrapParams::for_unwrap(
        KeyWrapAlgorithm::AesKw,
        UnwrapKeySpec {
            algorithm: KeyAlgorithm::Aes(SymmetricKeySize::Bits256),
            usage: KeyUsage::ALL,
            extractable: false,
        },
    ),
)?;
```

#### 4.3.4 Key Material and Handle Model

The protobuf protocol uses an opaque numeric key identifier:

```proto
message KeyHandle {
    uint64 id = 1;  // id=0 is reserved as invalid
}
```

Key import/export formats are represented by `KeyFormat`:

| Format | Use Case |
|--------|----------|
| `RAW` | Raw symmetric key bytes |
| `PEM` | PEM-encoded key material |
| `DER` | DER-encoded key material |
| `PKCS8` | PKCS#8 private/public key containers |
| `PUBLIC_KEY_ONLY` | Export/import public portion only |

Backend interface (`lib.rs`) key material sources for import are:

| Source | Use Case |
|--------|----------|
| `Plaintext(&[u8])` | Raw key bytes from secure storage |
| `Pem(&str)` | PEM-encoded key material |
| `Der(&[u8])` | DER-encoded key material |

### 4.4 Algorithm Registry

The API uses discriminated unions (enums) for algorithm specification:

```
Wire KeyAlgorithm (protobuf oneof)
├── symmetric (generic symmetric key)
├── aes(SymmetricKeySize)
├── hmac(HashAlgorithm)
├── cmac
├── rsa_bits (u32)
├── ec(EcCurve)
├── x25519 / x448
└── ed25519 / ed448

Backend KeyAlgorithm (Rust enum)
├── Symmetric | Aes(SymmetricKeySize) | Hmac(HashAlgorithm) | Cmac
├── Rsa { bits } | Ec { curve }
└── X25519 | Ed25519 | X448 | Ed448

HashAlgorithm
├── Raw                     # Pre-hashed data (for HMAC with external hash)
├── SHA-1, SHA-2 family (224/256/384/512/512-256)
└── SHA-3 family (224/256/384/512)

CipherMode
├── Block modes: ECB, CBC, CTR, CFB, OFB
└── AEAD: GCM, CCM

MacAlgorithm
├── HMAC-SHA1/224/256/384/512
├── HMAC-SHA3-256/384/512
└── CMAC
```

---

## 5. Streaming Context Pattern

### 5.1 Pattern Overview

All multi-step operations follow the **init → update → finish** pattern:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Streaming Context Lifecycle                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐    │
│   │  Init   │───>  │ Update  │ ───> │ Update  │ ───> │ Finish  │    │
│   │(Factory)│      │  (n=1)  │      │  (n=N)  │      │         │    │
│   └─────────┘      └─────────┘      └─────────┘      └─────────┘    │
│                         │                │                │         │
│                         ▼                ▼                ▼         │
│                    Accumulate       Accumulate      Produce         │
│                    state/data       state/data      final output    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Context Traits

| Trait | Purpose | Terminal Operation |
|-------|---------|-------------------|
| `StreamingContext` | Base trait with `update(&mut self, data: &[u8])` | - |
| `HashContext` | Cryptographic hashing | `finish() → Vec<u8>` |
| `MacContext` | Message authentication | `finish() → Vec<u8>` or `verify(expected)` |
| `CipherContext` | Encryption/Decryption | `finish(output)` + optional `tag()` |
| `SignContext` | Digital signature creation | `finish() → signature` |
| `VerifyContext` | Signature verification | `finish(signature) → bool` |
| `KeyAgreementContext` | ECDH/X25519 key agreement | `derive(peer_pub) → shared_secret` |

### 5.3 Memory Model

The streaming pattern enables:
- **Constant memory usage**: Process arbitrarily large data in chunks
- **Zero-copy where possible**: Borrowed references for input data
- **Output buffer reuse**: Caller-provided `&mut Vec<u8>` for cipher output

---

## 6. AEAD Support

Authenticated Encryption with Associated Data (AEAD) is a first-class feature:

### 6.1 Supported AEAD Modes

- AES-GCM (Galois/Counter Mode)
- AES-CCM (Counter with CBC-MAC)

### 6.2 AEAD Operation Flow

```
ENCRYPTION:
┌──────────────────────────────────────────────────────────────┐
│  cipher_encrypt(params, key)                                 │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                             │
│  │ CipherParams│ <── algorithm, iv, aad, tag_len             │
│  └─────────────┘    (or use CipherParams::aes_gcm() helper)  │
│       │                                                      │
│       ▼                                                      │
│  ctx.update(plaintext, &mut ciphertext)  ──> (multiple)      │
│       │                                                      │
│       ▼                                                      │
│  tag = ctx.finish(&mut ciphertext)?                          │
│           └──> Returns Some(tag) for AEAD modes              │
└──────────────────────────────────────────────────────────────┘

DECRYPTION:
┌──────────────────────────────────────────────────────────────┐
│  cipher_decrypt(params, key)                                 │
│       │                                                      │
│       ▼                                                      │
│  ctx.set_tag(expected_tag)  <── from transmission            │
│       │                                                      │
│       ▼                                                      │
│  ctx.update(ciphertext, &mut plaintext) ──> (multiple)       │
│       │                                                      │
│       ▼                                                      │
│  ctx.finish(&mut plaintext) ──> TagMismatch error if invalid │
└──────────────────────────────────────────────────────────────┘
```

**Convenience Constructors:**
```rust
// Quick AES-GCM setup
let params = CipherParams::aes_gcm(nonce);

// AES-GCM with AAD
let params = CipherParams::aes_gcm_with_aad(nonce, aad);

// Tag length is optional; defaults to 16 bytes in the wire contract
let params = CipherParams {
    mode: CipherMode::Gcm,
    iv: Some(nonce.to_vec()),
    aad: None,
    tag_len: None,
};
```

---

## 7. Signature Operations

### 7.1 Supported Algorithms

| Algorithm | Description |
|-----------|-------------|
| RSA PKCS#1 v1.5 | Traditional RSA signature with hash |
| RSA-PSS | Probabilistic Signature Scheme (recommended for RSA) |
| ECDSA | Elliptic Curve DSA (P-256, P-384, P-521, secp256k1) |
| Ed25519 | Edwards-curve DSA (fixed curve, recommended) |
| Ed448 | Edwards-curve DSA (448-bit, higher security margin) |

**RSA-PSS Salt Length Options:**
```rust
pub enum RsaPssSaltLen {
    HashLen,       // Salt = hash output length (recommended)
    Max,           // Maximum possible salt length
    Bytes(usize),  // Specific byte length
}
```

### 7.2 Sign/Verify Flow

```rust
// Signing
let signer = provider.signer(params, private_key)?;
signer.update(message)?;
let signature = signer.finish()?;

// Verification
let verifier = provider.verifier(params, public_key)?;
verifier.update(message)?;
let valid = verifier.finish(&signature)?;
```

---

## 8. Key Agreement

### 8.1 Supported Algorithms

- **ECDH**: Elliptic Curve Diffie-Hellman (P-256, P-384, P-521, secp256k1)
- **X25519**: Curve25519-based key exchange (recommended)
- **X448**: Curve448-based key exchange (higher security margin)

### 8.2 Key Derivation Flow

```
┌─────────────┐    ┌─────────────┐
│ Private Key │    │ Peer Public │
│   (local)   │    │    Key      │
└──────┬──────┘    └──────┬──────┘
       │                  │
       ▼                  │
┌──────────────────┐      │
│ KeyAgreementCtx  │<─────┘
│    .derive()     │
└────────┬─────────┘
         │
         ▼
   ┌───────────┐
   │  Shared   │
   │  Secret   │
   └───────────┘
```

---

## 9. Random Number Generation

```rust
pub trait RandomGenerator: Send + Sync {
    fn fill(&mut self, output: &mut [u8]) -> CryptoResult<()>;
    
    // Convenience methods with default implementations:
    fn generate(&mut self, len: usize) -> CryptoResult<Vec<u8>>;
    fn u32(&mut self) -> CryptoResult<u32>;
    fn u64(&mut self) -> CryptoResult<u64>;
    fn u32_range(&mut self, max: u32) -> CryptoResult<u32>;  // Unbiased
}
```

**Characteristics:**
- Thread-safe by design
- Fills caller-provided buffer
- Returns `EntropyUnavailable` if CSPRNG fails
- Unbiased range generation using rejection sampling

---

## 10. Key Derivation Functions

### 10.1 Supported KDFs

| Algorithm | Use Case |
|-----------|----------|
| **HKDF-SHA256/384/512** | Extract-and-expand KDF for key derivation from shared secrets |
| **PBKDF2-SHA256/384/512** | Password-based key derivation |
| **TLS12 EMS PRF SHA256/384** | TLS 1.2 Extended Master Secret PRF derivation |

### 10.2 KDF Usage

```rust
// HKDF for deriving keys from ECDH shared secret
let derived = provider.derive_key(KdfParams {
    key_handle: KeyHandle::new(1),
    algorithm: KdfAlgorithm::Hkdf(HashAlgorithm::Sha256),
    ikm: &shared_secret,
    salt: Some(b"application-salt"),
    info: Some(b"encryption-key"),
    output_len: 32,
})?;

// TLS 1.2 EMS PRF derivation
let ems = provider.derive_key(KdfParams {
    key_handle: KeyHandle::new(1),
    algorithm: KdfAlgorithm::Tls12Prf(Tls12PrfParams {
        hash: HashAlgorithm::Sha256,
        label: Tls12PrfLabel::ExtendedMasterSecret,
    }),
    ikm: &master_secret,
    salt: Some(&session_hash),
    info: Some(b"extended master secret"),
    output_len: 48,
})?;
```

---

## 10. Backend Extensibility

### 10.1 Backend Types

The backend interface `KeyBackendKind` enum identifies key storage location:

| Kind | Description |
|------|-------------|
| `Software` | In-memory software key |
| `Hardware(Hsm/Tpm/Pkcs11/SecureElement)` | Hardware-backed key storage |
| `OpaqueHandle` | Generic opaque reference |
| `Custom(String)` | Extensible custom backend type |

Note: the protobuf wire schema currently exposes hardware backends as flat enum values,
while the Rust backend API represents them as `KeyBackendKind::Hardware(HardwareBackend)`.

### 10.2 Implementing a New Backend

To add a new backend:

1. **Create key type** implementing `KeyObject`
2. **Implement `CryptoProvider`** with `type Key = YourKeyType`
3. **Implement context traits** for each supported operation
4. **Map backend errors** to `CryptoError` variants

```rust
pub struct HsmProvider { /* HSM connection state */ }

impl CryptoProvider for HsmProvider {
    type Key = HsmKeyHandle;
    
    fn hash(&self, algorithm: HashAlgorithm) 
        -> CryptoResult<Box<dyn HashContext>> {
        // Create HSM-backed hash context
    }
    // ... other methods
}
```

---

## 11. Thread Safety

All public types are designed for concurrent use:

| Component | Thread Safety |
|-----------|---------------|
| `CryptoProvider` | `Send + Sync` - shareable across threads |
| `KeyObject` | `Send + Sync` - keys can be shared |
| Context traits | `Box<dyn Trait>` - owned, single-threaded use |
| `RandomGenerator` | `Send + Sync` - concurrent RNG access |

**Note:** Streaming contexts are owned (`Box<dyn ...>`) and typically used by a single thread, but the trait bounds allow sending between threads if needed.

---

## 12. Security Considerations

### 12.1 Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Key Isolation** | Opaque handles prevent accidental key leakage |
| **Explicit Exportability** | `is_exportable()` flag controls key extraction |
| **Usage Restrictions** | `KeyUsage` bitfield limits key operations |
| **Authentication First** | AEAD modes for encryption by default |
| **Fail Secure** | Verification failures return error, not partial data |
| **Constant-Time Operations** | MAC/signature verification MUST be constant-time |
| **Memory Zeroization** | Sensitive data MUST be zeroized on drop |

### 12.2 Implementation Requirements

**CRITICAL:** Implementations MUST adhere to these security requirements:

1. **Constant-Time Comparison**: All MAC and signature verification MUST use constant-time comparison to prevent timing attacks. Use the `subtle` or `constant_time_eq` crates.

2. **Zeroization**: All types containing sensitive key material MUST implement the `Zeroize` trait (from the `zeroize` crate) and be zeroized when dropped.

3. **Nonce Handling**: Nonces MUST never be reused with the same key. Use strict nonce-management policies for GCM/CCM modes.

### 12.3 Recommended Practices

1. **Prefer AEAD modes** (GCM, CCM) over unauthenticated encryption
2. **Never reuse nonces/IVs** with the same key
3. **Use constant-time comparison** for MAC/signature verification
4. **Zeroize sensitive data** after use (implementation responsibility)
5. **Prefer Ed25519/X25519** for new systems (simpler, safer)
6. **Use RSA-PSS** over PKCS#1 v1.5 for RSA signatures
7. **Use PBKDF2 iteration counts appropriate for your threat model**
8. **Minimum key sizes**: RSA ≥ 2048-bit, EC ≥ P-256

### 12.4 Attack Surface Mitigation

| Attack Vector | Mitigation |
|--------------|------------|
| Side-channel | Backend implementation concern (constant-time ops) |
| Timing attacks | Constant-time comparison for all secrets |
| Key extraction | Opaque handles, exportability controls |
| Nonce reuse | Strict nonce uniqueness checks and generation policy |
| Downgrade | Application-level algorithm enforcement |
| Memory disclosure | Zeroize on drop, avoid swapping |

---

## 13. API Usage Patterns

### 13.1 Envelope Pattern

All operations are wrapped in `CryptoRequest` and `CryptoResponse` with a shared `request_id`.

```proto
message CryptoRequest {
  uint64 request_id = 1;
  oneof request { ... }
}

message CryptoResponse {
  uint64 request_id = 1;
  CryptoError error = 2;
  oneof response { ... }
}
```

### 13.2 Hash Streaming Flow

```text
1) send HashCreateRequest { algorithm: HASH_ALGORITHM_SHA256 }
2) receive HashCreateResponse { context_handle, output_size }
3) send N x HashUpdateRequest { context_handle, data }
4) send HashFinishRequest { context_handle }
5) receive HashFinishResponse { digest }
```

### 13.3 MAC Verify Flow

```text
1) MacCreateRequest { algorithm: MAC_ALGORITHM_HMAC_SHA256, key }
2) MacUpdateRequest { context_handle, data }
3) MacVerifyRequest { context_handle, expected_tag }
4) MacVerifyResponse { valid }
```

### 13.4 AEAD Decryption Flow (GCM/CCM)

```text
1) CipherCreateRequest {
     params: { mode: CIPHER_MODE_GCM, iv, aad, tag_len },
     key,
     encrypt: false
   }
2) CipherSetTagRequest { context_handle, tag }
3) repeat CipherUpdateRequest { context_handle, input }
4) CipherFinishRequest { context_handle }
5) on success: CipherFinishResponse { output, tag: none }
6) on auth failure: CryptoResponse.error.code = ERROR_CODE_TAG_MISMATCH
```

### 13.5 Key Discovery and Info

```text
1) FindKeyRequest { query: { label: "session-key" } }
2) FindKeyResponse { handle? }
3) if handle present -> GetKeyInfoRequest { handle }
4) GetKeyInfoResponse { info: { algorithm, usage, extractable, backend, size_bits, label } }
```

### 13.6 ECDH + HKDF Wire Pattern

```text
1) KeyAgreementRequest {
     algorithm: KEY_AGREEMENT_ALGORITHM_X25519,
     private_key,
     peer_public_key
   }
2) KeyAgreementResponse { shared_secret }
3) DeriveKeyRequest {
     algorithm: KDF_ALGORITHM_HKDF_SHA256,
     key,
     salt,
     info,
     output_len
   }
4) DeriveKeyResponse { derived_key }
```

---

## 14. Future Extensibility

The design accommodates future additions:

| Area | Extension Point | Status |
|------|-----------------|--------|
| New hash algorithms | Add variant to `HashAlgorithm` | Planned |
| Post-quantum crypto | Add new `KeyAlgorithm` variants (e.g., `Kyber`, `Dilithium`) | Planned |
| Key derivation (KDF) | `derive_key()` method | ✓ Implemented |
| Password hashing | Add memory-hard KDF variants (Argon2id/scrypt) | Planned |
| Certificate operations | Extend `KeyFormat` and add signing methods | Planned |
| Batch operations | Add batch methods for HSM efficiency | Planned |
| Async operations | Add async variants of provider methods | Considered |

---

## 15. Dependencies

The API is designed with minimal dependencies:

- `core::fmt::Debug` - Debug trait derivation
- `std::error::Error` - Standard error trait implementation

No external cryptographic crates are imported—implementations bring their own.

---

## 16. Glossary

| Term | Definition |
|------|------------|
| **AEAD** | Authenticated Encryption with Associated Data |
| **CCM** | Counter with CBC-MAC |
| **DER** | Distinguished Encoding Rules (binary format) |
| **ECDH** | Elliptic Curve Diffie-Hellman |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm |
| **Ed25519/Ed448** | Edwards-curve Digital Signature Algorithms |
| **GCM** | Galois/Counter Mode |
| **HKDF** | HMAC-based Key Derivation Function |
| **HSM** | Hardware Security Module |
| **KDF** | Key Derivation Function |
| **PEM** | Privacy-Enhanced Mail (Base64 encoded format) |
| **PKCS#11** | Public-Key Cryptography Standard for hardware tokens |
| **RSA-PSS** | RSA Probabilistic Signature Scheme |
| **TPM** | Trusted Platform Module |
| **X25519/X448** | Elliptic curve Diffie-Hellman key exchange functions |

---

## 17. Daemon Architecture (cryptod)

### 17.1 Overview

The reference implementation includes a daemon (`cryptod`) that provides cryptographic services over a Unix domain socket using Protocol Buffers.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Client Process                             │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                   C++ Client Library                        │    │
│  │  Client::connect() → hash() / mac() / cipher_*() / etc.     │    │
│  └──────────────────────────────┬──────────────────────────────┘    │
└─────────────────────────────────┼───────────────────────────────────┘
                                  │ Protobuf over
                                  │ SOCK_SEQPACKET
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          cryptod Daemon                             │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                      Handler Layer                          │    │
│  │  Protobuf decode → dispatch → CryptoProvider → encode       │    │
│  └──────────────────────────────┬──────────────────────────────┘    │
│                                 ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  Native CryptoProvider                      │    │
│  │  RustCrypto crates: aes, sha2, hmac, cbc, etc.              │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### 17.2 Socket Communication

| Property | Value |
|----------|-------|
| **Socket Type** | `SOCK_SEQPACKET` (Unix domain) |
| **Default Path** | `/tmp/cryptod.sock` |
| **Protocol** | Protocol Buffers using `CryptoRequest` / `CryptoResponse` envelopes |
| **Request/Response** | Synchronous per-message |

### 17.3 Building the Daemon

```bash
# Build daemon
cargo build --release
```

### 17.4 Starting the Daemon

```bash
# Default socket
./target/release/cryptod

# Custom socket path
./target/release/cryptod --socket /var/run/cryptod.sock
```

---

## 18. C++ Client Library

### 18.1 Installation

The C++ client requires:
- CMake 3.16+
- C++20 compiler
- Protobuf development libraries
- Google Test (for tests)

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y libprotobuf-dev protobuf-compiler libgtest-dev

# Build
cd client/cpp
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j4
```

### 18.2 Client API

```cpp
#include "cryptod/client.hpp"

// Connect to daemon
auto client = cryptod::Client::connect("/tmp/cryptod.sock");

// Key Management
auto key = client->create_key(CreateKeyParams::symmetric256());
auto key = client->import_key(ImportKeyParams::symmetric256(material));
client->delete_key(key);

// Hashing (streaming)
auto ctx = client->hash(HashAlgorithm::Sha256);
ctx->update("data");
auto digest = ctx->finish();

// MAC (streaming)
auto ctx = client->mac(MacAlgorithm::HmacSha256, key);
ctx->update("message");
auto tag = ctx->finish();
bool valid = ctx->verify(expected_tag);

// Cipher (streaming)
auto enc = client->cipher_encrypt(CipherParams::aes_cbc(iv), key);
auto ciphertext = enc->update(plaintext);
ciphertext.append(enc->finish());

auto dec = client->cipher_decrypt(CipherParams::aes_cbc(iv), key);
auto plaintext = dec->update(ciphertext);
plaintext.append(dec->finish());

// Random generation
auto random = client->generate_random(32);
```

### 18.3 Key Parameters

Key creation and import use `SymmetricKeySize` enum:

```cpp
enum class SymmetricKeySize {
    Bits128 = 128,
    Bits192 = 192,
    Bits256 = 256,
    Bits384 = 384,
    Bits512 = 512,
};

// Create key (generates random material)
auto params = CreateKeyParams::symmetric256();
auto params = CreateKeyParams::symmetric(SymmetricKeySize::Bits128);

// Import key (uses provided material)
auto params = ImportKeyParams::symmetric256(key_material);
auto params = ImportKeyParams::symmetric(SymmetricKeySize::Bits256, key_material);
```

### 18.4 Error Handling

```cpp
try {
    auto client = Client::connect("/tmp/cryptod.sock");
    // ... operations
} catch (const CryptoException& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    // e.code() returns ErrorCode enum
}
```

---

## 19. Implementation Status

### 19.1 Daemon (cryptod)

| Feature | Status |
|---------|--------|
| Hash operations | ✅ SHA-256, SHA-384, SHA-512 |
| MAC operations | ✅ HMAC-SHA256 |
| Symmetric cipher | ✅ AES-CBC (128/192/256) |
| AEAD cipher | ⏳ AES-GCM (planned) |
| Key management | ✅ Create, import, export, delete |
| Random generation | ✅ Cryptographically secure |
| Signatures | ⏳ Planned |
| Key agreement | ⏳ Planned |
| KDF | ⏳ Planned |

### 19.2 C++ Client Library

| Feature | Status |
|---------|--------|
| Connection management | ✅ Unix socket, SEQPACKET |
| Hash streaming | ✅ Full support |
| MAC streaming | ✅ Including verify |
| Cipher streaming | ✅ Encrypt/decrypt |
| Key management | ✅ Create, import, export, delete |
| Random generation | ✅ Full support |
| Error handling | ✅ Exception-based |

### 19.3 Test Coverage

```bash
# Run all tests (starts daemon automatically)
./scripts/run_tests.sh

# Run Rust tests only
cargo test

# Run C++ tests only (daemon must be running)
cd client/cpp/build && ./cryptod_client_tests
```

**Test vectors verified:**
- SHA-256: NIST test vectors (empty, "abc", "hello world")
- HMAC-SHA256: RFC 4231 Test Case 2
- AES-256-CBC: NIST SP 800-38A test vector

---

## 20. Project Structure

```
cryptod/
├── crates/
│   ├── crypto-api/       # Rust API traits and types
│   ├── crypto-native/    # Native backend (RustCrypto)
│   └── cryptod/          # Daemon binary
│       ├── src/
│       │   ├── main.rs   # Entry point
│       │   ├── server.rs # Socket server
│       │   ├── handler.rs# Request dispatch
│       │   └── proto.rs  # Protobuf helpers
│       └── build.rs      # Prost code generation
├── client/
│   └── cpp/              # C++ client library
│       ├── include/cryptod/
│       │   ├── client.hpp
│       │   ├── key.hpp
│       │   ├── algorithm.hpp
│       │   ├── hash.hpp
│       │   ├── mac.hpp
│       │   └── cipher.hpp
│       ├── src/
│       └── tests/
│           ├── test_hash.cpp
│           ├── test_mac.cpp
│           ├── test_cipher.cpp
│           └── test_utils.hpp  # Common helpers (hex_to_bytes)
├── proto/
│   └── crypto_api.proto  # Protobuf definitions
├── scripts/
│   └── run_tests.sh      # Test runner with daemon management
└── README.md  # This document
```
