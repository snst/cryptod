//! crypto_api.rs
//!
//! Interface-only cryptographic API design for Rust.
//!
//! Goals:
//! - Backend-agnostic
//! - Supports opaque key handles and plaintext key material
//! - Streaming API pattern: init -> update -> finish
//! - Suitable for HSMs, TPMs, software crypto, enclave backends
//! - Extensible algorithm registry
//! - Zero-copy friendly
//! - AEAD support (GCM, CCM, etc.)
//! - Signing/verification
//! - ECDH key agreement
//! - Key derivation functions (HKDF, PBKDF2)
//! - Provider capability discovery
//!
//! NOTE:
//! This file intentionally contains ONLY interfaces and types.
//! No implementation logic is included.
//!
//! SECURITY:
//! Implementations MUST:
//! - Use constant-time comparison for MAC/signature verification
//! - Zeroize sensitive key material when dropped (use `zeroize` crate)
//! - Prevent nonce reuse for AEAD modes

#![allow(unused)]

use core::fmt::Debug;
use std::error::Error;

// Re-export bitflags for KeyUsage
pub use bitflags::bitflags;

//
// ============================================================
// Error Model
// ============================================================
//

pub type CryptoResult<T> = Result<T, CryptoError>;

/// Comprehensive error type for cryptographic operations.
///
/// Simplified: removed Option wrappers where a default makes sense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Key is malformed, wrong type, or incompatible with the operation.
    InvalidKey(String),
    /// Requested algorithm is not supported by this provider.
    InvalidAlgorithm(String),
    /// Operation called in wrong context state (e.g., update after finish).
    InvalidState(String),
    /// Input data is malformed or out of valid range.
    InvalidInput(String),
    /// Nonce/IV has wrong size, is missing, or was reused.
    InvalidNonce { expected_len: usize, actual_len: usize },
    /// AEAD authentication tag verification failed.
    TagMismatch,
    /// Input exceeds algorithm or implementation limits.
    DataTooLarge { max_size: usize },
    /// MAC or signature verification failed.
    AuthenticationFailed,
    /// Feature or algorithm not implemented by this backend.
    Unsupported(String),
    /// Backend-specific failure with details.
    BackendError { code: i32, message: String },
    /// Cryptographically secure RNG source is unavailable.
    EntropyUnavailable,
    /// Output buffer is too small for the result.
    BufferTooSmall { required: usize, provided: usize },
    /// Key was not found (for hardware backends with key storage).
    KeyNotFound(String),
    /// Key has expired or been revoked.
    KeyExpired,
    /// Operation not permitted by key usage flags.
    UsageNotPermitted(String),
    /// Hardware device communication failure.
    DeviceError(String),
    /// Operation timed out (e.g., waiting for hardware).
    Timeout,
}

impl CryptoError {
    /// Create an InvalidKey error with a reason.
    pub fn invalid_key(reason: impl Into<String>) -> Self {
        Self::InvalidKey(reason.into())
    }

    /// Create an InvalidAlgorithm error.
    pub fn invalid_algorithm(algorithm: impl Into<String>) -> Self {
        Self::InvalidAlgorithm(algorithm.into())
    }

    /// Create a BackendError with message.
    pub fn backend_error(message: impl Into<String>) -> Self {
        Self::BackendError { code: 0, message: message.into() }
    }

    /// Create a BufferTooSmall error.
    pub fn buffer_too_small(required: usize, provided: usize) -> Self {
        Self::BufferTooSmall { required, provided }
    }

    /// Create an Unsupported error.
    pub fn unsupported(feature: impl Into<String>) -> Self {
        Self::Unsupported(feature.into())
    }

    /// Create an InvalidInput error.
    pub fn invalid_input(reason: impl Into<String>) -> Self {
        Self::InvalidInput(reason.into())
    }

    /// Create an InvalidState error.
    pub fn invalid_state(reason: impl Into<String>) -> Self {
        Self::InvalidState(reason.into())
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey(reason) => write!(f, "InvalidKey: {}", reason),
            Self::InvalidAlgorithm(alg) => write!(f, "InvalidAlgorithm: {}", alg),
            Self::InvalidState(reason) => write!(f, "InvalidState: {}", reason),
            Self::InvalidInput(reason) => write!(f, "InvalidInput: {}", reason),
            Self::InvalidNonce { expected_len, actual_len } => {
                write!(f, "InvalidNonce: expected {} bytes, got {}", expected_len, actual_len)
            }
            Self::TagMismatch => write!(f, "TagMismatch"),
            Self::DataTooLarge { max_size } => write!(f, "DataTooLarge: max {} bytes", max_size),
            Self::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Self::Unsupported(feature) => write!(f, "Unsupported: {}", feature),
            Self::BackendError { code, message } => {
                write!(f, "BackendError (code {}): {}", code, message)
            }
            Self::EntropyUnavailable => write!(f, "EntropyUnavailable"),
            Self::BufferTooSmall { required, provided } => {
                write!(f, "BufferTooSmall: need {} bytes, got {}", required, provided)
            }
            Self::KeyNotFound(id) => write!(f, "KeyNotFound: {}", id),
            Self::KeyExpired => write!(f, "KeyExpired"),
            Self::UsageNotPermitted(op) => write!(f, "UsageNotPermitted: {}", op),
            Self::DeviceError(msg) => write!(f, "DeviceError: {}", msg),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}
impl Error for CryptoError {}

//
// ============================================================
// Backend Abstraction
// ============================================================
//

/// Capability flags indicating what a provider supports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub algorithms: Vec<KeyAlgorithm>,
    pub hash_algorithms: Vec<HashAlgorithm>,
    pub cipher_modes: Vec<CipherMode>,
    pub signature_algorithms: Vec<SignatureAlgorithm>,
}

pub trait CryptoProvider: Send + Sync {
    //
    // Provider information
    //

    /// Returns the name/identifier of this provider.
    fn name(&self) -> &str;

    /// Query provider capabilities for algorithm support discovery.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Check if a specific algorithm is supported.
    fn supports_algorithm(&self, algorithm: &KeyAlgorithm) -> bool {
        self.capabilities().algorithms.contains(algorithm)
    }

    //
    // Key management
    //

    /// Create a new key and store it in the provider.
    /// Returns a handle to the created key.
    fn create_key(&self, params: CreateKeyParams) -> CryptoResult<KeyHandle>;

    /// Import a key from external material.
    /// Returns a handle to the imported key.
    fn import_key(&self, params: ImportKeyParams) -> CryptoResult<KeyHandle>;

    /// Get information about a key.
    fn key_info(&self, key: &KeyHandle) -> CryptoResult<KeyInfo>;

    /// Find a single key matching the query.
    /// Returns None if no key matches.
    fn find_key(&self, query: KeyQuery) -> CryptoResult<Option<KeyHandle>>;

    /// Export key material (if key is extractable).
    fn export_key(
        &self,
        key: &KeyHandle,
        format: KeyFormat,
    ) -> CryptoResult<Vec<u8>>;

    /// Delete a key from the provider.
    fn delete_key(&self, key: &KeyHandle) -> CryptoResult<()>;

    /// Wrap a key using a wrapping key (for secure key export).
    fn wrap_key(
        &self,
        key_to_wrap: &KeyHandle,
        wrapping_key: &KeyHandle,
        params: KeyWrapParams,
    ) -> CryptoResult<Vec<u8>>;

    /// Unwrap a previously wrapped key.
    /// Returns a handle to the unwrapped key stored in the provider.
    fn unwrap_key(
        &self,
        wrapped_key: &[u8],
        unwrapping_key: &KeyHandle,
        params: KeyWrapParams,
    ) -> CryptoResult<KeyHandle>;

    //
    // Primitive factories (streaming)
    //

    fn hash(&self, algorithm: HashAlgorithm)
        -> CryptoResult<Box<dyn HashContext>>;

    fn hmac(
        &self,
        algorithm: MacAlgorithm,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn MacContext>>;

    fn cipher_encrypt(
        &self,
        params: CipherParams,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn CipherContext>>;

    fn cipher_decrypt(
        &self,
        params: CipherParams,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn CipherContext>>;

    fn signer(
        &self,
        params: SignatureParams,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn SignContext>>;

    fn verifier(
        &self,
        params: SignatureParams,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn VerifyContext>>;

    fn key_agreement(
        &self,
        params: KeyAgreementParams,
        private_key: &KeyHandle,
    ) -> CryptoResult<Box<dyn KeyAgreementContext>>;

    fn random(&self) -> CryptoResult<Box<dyn RandomGenerator>>;

    //
    // Key Derivation Functions
    //

    /// Derive key material using HKDF or other KDF.
    fn derive_key(
        &self,
        params: KdfParams,
    ) -> CryptoResult<Vec<u8>>;
}

//
// ============================================================
// Abstract Key Object
// ============================================================
//

/// Simplified key trait - just returns key info.
///
/// Instead of 6 separate methods, implementors return a single KeyInfo struct.
pub trait KeyObject: Debug + Send + Sync {
    /// Get all key metadata at once.
    fn info(&self) -> &KeyInfo;

    /// Convenience: get the key algorithm.
    fn algorithm(&self) -> &KeyAlgorithm {
        &self.info().algorithm
    }

    /// Convenience: get the key usage flags.
    fn usage(&self) -> KeyUsage {
        self.info().usage
    }

    /// Convenience: check if key is exportable.
    fn is_exportable(&self) -> bool {
        self.info().extractable
    }
}

/// All key metadata in one struct.
///
/// Simplifies KeyObject implementations - just store and return this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Key identifier (always auto-generated numeric).
    pub id: Option<KeyId>,
    /// Optional human-readable label for key lookup.
    pub label: String,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Permitted operations.
    pub usage: KeyUsage,
    /// Whether the key can be exported.
    pub extractable: bool,
    /// Backend type.
    pub backend: KeyBackendKind,
    /// Key size in bits (if applicable).
    pub size_bits: Option<usize>,
}

impl KeyInfo {

    /*
    /// Create a new symmetric software key.
    pub fn symmetric(size_bits: usize) -> Self {
        Self {
            id: None,
            label: None,
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            backend: KeyBackendKind::Software,
            size_bits: Some(size_bits),
        }
    }

    /// Create a new asymmetric software key.
    pub fn asymmetric(algorithm: KeyAlgorithm) -> Self {
        Self {
            id: None,
            label: None,
            algorithm,
            usage: KeyUsage::ALL,
            extractable: true,
            backend: KeyBackendKind::Software,
            size_bits: None,
        }
    }

    /// Create a new software key info (legacy, prefer symmetric/asymmetric).
    pub fn software(algorithm: KeyAlgorithm) -> Self {
        Self {
            id: None,
            label: None,
            algorithm,
            usage: KeyUsage::ALL,
            extractable: true,
            backend: KeyBackendKind::Software,
            size_bits: None,
        }
    }

    /// Create a new hardware key info.
    pub fn hardware(algorithm: KeyAlgorithm, hw: HardwareBackend) -> Self {
        Self {
            id: None,
            label: None,
            algorithm,
            usage: KeyUsage::ALL,
            extractable: false, // Hardware keys typically not extractable
            backend: KeyBackendKind::Hardware(hw),
            size_bits: None,
        }
    }

    /// Set the key ID.
    pub fn with_id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the key usage.
    pub fn with_usage(mut self, usage: KeyUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Set extractable flag.
    pub fn with_extractable(mut self, extractable: bool) -> Self {
        self.extractable = extractable;
        self
    }

    /// Set the key size in bits.
    pub fn with_size_bits(mut self, bits: usize) -> Self {
        self.size_bits = Some(bits);
        self
    }

    /// Set the key label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    */
}

/// Backend kind for key storage.
/// 
/// Simplified: Hardware variants consolidated, custom included.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyBackendKind {
    /// Software-based key storage.
    Software,
    /// Hardware-backed key storage with specific type.
    Hardware(HardwareBackend),
    /// Opaque handle (backend-specific).
    OpaqueHandle,
    /// Custom/extensible backend type.
    Custom(String),
}

/// Hardware backend types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HardwareBackend {
    Hsm,
    Tpm,
    Pkcs11,
    SecureElement,
}

//
// ============================================================
// Key Import / Export
// ============================================================
//

#[derive(Debug, Clone)]
pub struct ImportKeyParams<'a> {
    pub label: String,
    pub algorithm: KeyAlgorithm,
    pub format: KeyFormat,
    pub material: KeyMaterial<'a>,
    pub usage: KeyUsage,
    pub extractable: bool,
}

impl<'a> ImportKeyParams<'a> {

    /*
    /// Create import params for raw key bytes.
    pub fn raw(algorithm: KeyAlgorithm, data: &'a [u8]) -> Self {
        Self {
            label: None,
            algorithm,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(data),
            usage: KeyUsage::ALL,
            extractable: true,
        }
    }
    

    /// Create import params for a symmetric key.
    pub fn symmetric(data: &'a [u8]) -> Self {
        Self::raw(KeyAlgorithm::Symmetric, data)
    }

    
    /// Set a label for the imported key.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set usage flags.
    pub fn with_usage(mut self, usage: KeyUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Set extractable flag.
    pub fn with_extractable(mut self, extractable: bool) -> Self {
        self.extractable = extractable;
        self
    }*/
}

/// Parameters for creating a new key.
#[derive(Debug, Clone)]
pub struct CreateKeyParams {
    /// Optional label/name for the key.
    pub label: String,
    pub algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub extractable: bool,
    /// Key size in bits (required for symmetric keys).
    pub size_bits: Option<usize>,
}

impl CreateKeyParams {
    /* 
    /// Create params for generating a generic symmetric key.
    pub fn symmetric(size_bits: usize) -> Self {
        Self {
            label: None,
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(size_bits),
        }
    }

    /// Create params for a 128-bit symmetric key.
    pub fn symmetric_128() -> Self {
        Self::symmetric(128)
    }

    /// Create params for a 256-bit symmetric key.
    pub fn symmetric_256() -> Self {
        Self::symmetric(256)
    }

    /// Create params for an asymmetric key.
    pub fn asymmetric(algorithm: KeyAlgorithm) -> Self {
        Self {
            label: None,
            algorithm,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: None,
        }
    }

    /// Set a label for the key.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set usage flags.
    pub fn with_usage(mut self, usage: KeyUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Set extractable flag.
    pub fn with_extractable(mut self, extractable: bool) -> Self {
        self.extractable = extractable;
        self
    }

    /// Override the key size.
    pub fn with_size_bits(mut self, size_bits: usize) -> Self {
        self.size_bits = Some(size_bits);
        self
    }
    */
}

/// Type alias for backward compatibility.
pub type GenerateKeyParams = CreateKeyParams;

#[derive(Debug, Clone)]
pub enum KeyMaterial<'a> {
    /// Raw plaintext key bytes.
    Plaintext(&'a [u8]),
    /// PEM-encoded key.
    Pem(&'a str),
    /// DER-encoded key.
    Der(&'a [u8]),
}

/// Type alias for key identifiers.
pub type KeyId = u64;

/// Invalid/uninitialized key ID value.
pub const INVALID_KEY_ID: KeyId = 0;

/// Opaque handle to a key managed by a provider.
/// An opaque handle to a key stored in the provider.
///
/// KeyHandle is always a numeric ID assigned by the provider when a key
/// is created or imported. To find a key by label, use `find_key()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub KeyId);

impl KeyHandle {
    /// Create a handle from a numeric ID.
    pub fn new(id: KeyId) -> Self {
        Self(id)
    }

    /// Get the numeric key ID.
    pub fn id(&self) -> KeyId {
        self.0
    }
}

impl From<KeyId> for KeyHandle {
    fn from(id: KeyId) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyHandle({})", self.0)
    }
}

//
// ============================================================
// Key Query (for finding keys)
// ============================================================
//

/// Query parameters for finding keys in a provider.
#[derive(Debug, Clone, Default)]
pub struct KeyQuery {
    /// Filter by key label (exact match).
    pub label: String,
}

impl KeyQuery {
    /// Find keys by exact label.
    pub fn by_label(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            ..Self::default()
        }
    }
}

//
// ============================================================
// Key Wrapping
// ============================================================
//

/// Unified parameters for key wrapping/unwrapping operations.
///
/// For wrapping: only `algorithm` and `iv` are needed.
/// For unwrapping: also provide `unwrap_key_spec`.
#[derive(Debug, Clone)]
pub struct KeyWrapParams {
    /// Wrapping algorithm (e.g., AES-KW, AES-GCM).
    pub algorithm: KeyWrapAlgorithm,
    /// Optional IV/nonce for algorithms that require it.
    pub iv: Option<Vec<u8>>,
    /// Specification for the unwrapped key (only needed for unwrap operations).
    pub unwrap_key_spec: Option<UnwrapKeySpec>,
}

/// Specification for an unwrapped key.
#[derive(Debug, Clone)]
pub struct UnwrapKeySpec {
    /// Expected algorithm of the unwrapped key.
    pub algorithm: KeyAlgorithm,
    /// Usage flags for the unwrapped key.
    pub usage: KeyUsage,
    /// Whether the unwrapped key can be exported.
    pub extractable: bool,
}

impl KeyWrapParams {
    /// Create params for wrapping (no unwrap spec needed).
    pub fn for_wrap(algorithm: KeyWrapAlgorithm) -> Self {
        Self { algorithm, iv: None, unwrap_key_spec: None }
    }

    /// Create params for unwrapping with key specification.
    pub fn for_unwrap(algorithm: KeyWrapAlgorithm, spec: UnwrapKeySpec) -> Self {
        Self { algorithm, iv: None, unwrap_key_spec: Some(spec) }
    }

    /// Add IV/nonce.
    pub fn with_iv(mut self, iv: Vec<u8>) -> Self {
        self.iv = Some(iv);
        self
    }
}

/// Key wrapping algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// AES Key Wrap (RFC 3394).
    AesKw,
    /// AES Key Wrap with Padding (RFC 5649).
    AesKwp,
    /// AES-GCM for key wrapping.
    AesGcm,
}

//
// ============================================================
// Key Derivation Functions
// ============================================================
//

/// Parameters for key derivation.
#[derive(Debug, Clone)]
pub struct KdfParams<'a> {
    pub key_handle: KeyHandle,
    pub algorithm: KdfAlgorithm,
    /// Input key material (IKM).
    pub ikm: &'a [u8],
    /// Salt (optional for some algorithms).
    pub salt: Option<&'a [u8]>,
    /// Info/context (for HKDF).
    pub info: Option<&'a [u8]>,
    /// Output length in bytes.
    pub output_len: usize,
}

/// Supported key derivation algorithms.
///
/// Simplified: complex params extracted to separate structs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// HKDF with specified hash.
    Hkdf(HashAlgorithm),
    /// PBKDF2 with specified parameters.
    Pbkdf2(Pbkdf2Params),
    /// TLS 1.2 PRF (RFC 5246) for key derivation.
    /// Used for master secret derivation, key expansion, etc.
    Tls12Prf(Tls12PrfParams),
}

/// PBKDF2 parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbkdf2Params {
    pub hash: HashAlgorithm,
    pub iterations: u32,
}

impl Pbkdf2Params {
    pub fn new(hash: HashAlgorithm, iterations: u32) -> Self {
        Self { hash, iterations }
    }

    /// SHA-256 with recommended iteration count.
    pub fn sha256(iterations: u32) -> Self {
        Self { hash: HashAlgorithm::Sha256, iterations }
    }
}

/// TLS 1.2 PRF parameters (RFC 5246).
///
/// The PRF is defined as: PRF(secret, label, seed) = P_<hash>(secret, label + seed)
/// where P_hash uses HMAC with the specified hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tls12PrfParams {
    /// Hash algorithm for the PRF (typically SHA-256 or SHA-384).
    pub hash: HashAlgorithm,
    /// PRF label identifying the derivation purpose.
    pub label: Tls12PrfLabel,
}

/// Standard TLS 1.2 PRF labels (RFC 5246, RFC 4279, RFC 7627).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12PrfLabel {
    /// "master secret" - derives master secret from pre-master secret.
    MasterSecret,
    /// "extended master secret" - derives master secret using session hash (RFC 7627).
    ExtendedMasterSecret,
    /// "key expansion" - derives key block from master secret.
    KeyExpansion,
    /// "client finished" - derives Finished message verify_data.
    ClientFinished,
    /// "server finished" - derives Finished message verify_data.
    ServerFinished,
}

impl Tls12PrfParams {
    /// Create params for TLS 1.2 PSK master secret derivation with SHA-256.
    pub fn psk_master_secret() -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            label: Tls12PrfLabel::MasterSecret,
        }
    }

    /// Create params for TLS 1.2 key expansion with SHA-256.
    pub fn key_expansion() -> Self {
        Self {
            hash: HashAlgorithm::Sha256,
            label: Tls12PrfLabel::KeyExpansion,
        }
    }

    /// Create params with a specific hash algorithm.
    pub fn with_hash(hash: HashAlgorithm, label: Tls12PrfLabel) -> Self {
        Self { hash, label }
    }
}

impl Tls12PrfLabel {
    /// Returns the RFC-defined label string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MasterSecret => "master secret",
            Self::ExtendedMasterSecret => "extended master secret",
            Self::KeyExpansion => "key expansion",
            Self::ClientFinished => "client finished",
            Self::ServerFinished => "server finished",
        }
    }

    /// Returns the label as bytes.
    pub fn as_bytes(&self) -> &'static [u8] {
        self.as_str().as_bytes()
    }
}

/// Unified key format for import and export operations.
///
/// Merged from KeyFormat and ExportFormat for simplicity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// Raw key bytes.
    Raw,
    /// PEM-encoded.
    Pem,
    /// DER-encoded.
    Der,
    /// PKCS#8 format (private keys).
    Pkcs8,
    /// Export only the public key portion.
    PublicKeyOnly,
}

bitflags! {
    /// Key usage flags using bitflags for efficient storage and operations.
    ///
    /// Simplified from struct with 7 boolean fields.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct KeyUsage: u8 {
        /// Key can be used for encryption.
        const ENCRYPT = 0b0000001;
        /// Key can be used for decryption.
        const DECRYPT = 0b0000010;
        /// Key can be used for signing.
        const SIGN    = 0b0000100;
        /// Key can be used for verification.
        const VERIFY  = 0b0001000;
        /// Key can be used for key derivation.
        const DERIVE  = 0b0010000;
        /// Key can be used to wrap other keys.
        const WRAP    = 0b0100000;
        /// Key can be used to unwrap other keys.
        const UNWRAP  = 0b1000000;
        /// All operations permitted.
        const ALL     = 0b1111111;
    }
}

impl KeyUsage {
    /// Encryption only.
    pub const ENCRYPT_ONLY: Self = Self::ENCRYPT;
    /// Decryption only.
    pub const DECRYPT_ONLY: Self = Self::DECRYPT;
    /// Signing only.
    pub const SIGN_ONLY: Self = Self::SIGN;
    /// Verification only.
    pub const VERIFY_ONLY: Self = Self::VERIFY;
    /// Key derivation only.
    pub const DERIVE_ONLY: Self = Self::DERIVE;
    /// Symmetric encryption (encrypt + decrypt).
    pub const SYMMETRIC: Self = Self::ENCRYPT.union(Self::DECRYPT);
    /// Asymmetric signing (sign + verify).
    pub const ASYMMETRIC_SIGN: Self = Self::SIGN.union(Self::VERIFY);
}

//
// ============================================================
// Algorithms
// ============================================================
//

/// Key algorithm type.
///
/// For symmetric keys: `Symmetric`, `Aes`, `Hmac`, and `Cmac` are all
/// interchangeable - they represent the *intended* use, not a restriction.
/// A 256-bit key marked as `Aes(Bits256)` can still be used for HMAC-SHA256.
/// Use `is_symmetric()` to check if a key can be used for symmetric operations.
///
/// For asymmetric keys: algorithms are NOT interchangeable (RSA ≠ EC ≠ Ed25519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Generic symmetric key (can be used for AES, HMAC, CMAC, etc.)
    Symmetric,

    /// Symmetric key intended for AES encryption.
    /// Size determines valid AES variants (128, 192, 256 bits).
    /// Can still be used for HMAC/CMAC if desired.
    Aes(SymmetricKeySize),

    /// Symmetric key intended for HMAC.
    /// The hash algorithm is a hint; key can still be used for AES/CMAC.
    Hmac(HashAlgorithm),

    /// Symmetric key intended for CMAC (AES-CMAC).
    /// Can still be used for other symmetric operations.
    Cmac,

    /// RSA keypair.
    Rsa { bits: usize },

    /// Elliptic curve keypair.
    Ec { curve: EcCurve },

    /// X25519 key agreement.
    X25519,
    /// Ed25519 signing.
    Ed25519,
    /// X448 key agreement.
    X448,
    /// Ed448 signing.
    Ed448,
}

impl KeyAlgorithm {
    /// Check if this is a symmetric key algorithm.
    /// All symmetric variants are interchangeable for operations.
    pub fn is_symmetric(&self) -> bool {
        matches!(self, Self::Symmetric | Self::Aes(_) | Self::Hmac(_) | Self::Cmac)
    }

    /// Check if this is an asymmetric key algorithm.
    pub fn is_asymmetric(&self) -> bool {
        !self.is_symmetric()
    }

    /// Create a generic symmetric key algorithm.
    pub fn symmetric() -> Self {
        Self::Symmetric
    }

    /// Create an AES key algorithm with the given size.
    pub fn aes(size: SymmetricKeySize) -> Self {
        Self::Aes(size)
    }

    /// Create an HMAC key algorithm with the given hash.
    pub fn hmac(hash: HashAlgorithm) -> Self {
        Self::Hmac(hash)
    }
}

/// Symmetric key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymmetricKeySize {
    Bits128,
    Bits192,
    Bits256,
    Bits384,
    Bits512,
}

impl SymmetricKeySize {
    pub fn bits(&self) -> usize {
        match self {
            Self::Bits128 => 128,
            Self::Bits192 => 192,
            Self::Bits256 => 256,
            Self::Bits384 => 384,
            Self::Bits512 => 512,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }

    /// Try to create from a bit size.
    pub fn from_bits(bits: usize) -> Option<Self> {
        match bits {
            128 => Some(Self::Bits128),
            192 => Some(Self::Bits192),
            256 => Some(Self::Bits256),
            384 => Some(Self::Bits384),
            512 => Some(Self::Bits512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// Raw/pre-hashed data (used for HMAC with external hash).
    Raw,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    /// Returns the output size in bytes.
    /// Returns None for Raw since the size depends on the pre-hashed data.
    pub fn output_size(&self) -> Option<usize> {
        match self {
            Self::Raw => None,
            Self::Sha1 => Some(20),
            Self::Sha224 | Self::Sha3_224 => Some(28),
            Self::Sha256 | Self::Sha512_256 | Self::Sha3_256 => Some(32),
            Self::Sha384 | Self::Sha3_384 => Some(48),
            Self::Sha512 | Self::Sha3_512 => Some(64),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    Hmac(HashAlgorithm),
    Cmac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    Aes(CipherMode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Ecb,
    Cbc,
    Ctr,
    Cfb,
    Ofb,

    //
    // AEAD modes
    //

    Gcm,
    Ccm,
}

impl CipherMode {
    /// Returns true if this mode provides authenticated encryption.
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::Gcm | Self::Ccm)
    }

    /// Returns the recommended nonce/IV size in bytes.
    pub fn recommended_nonce_size(&self) -> Option<usize> {
        match self {
            Self::Gcm => Some(12),
            Self::Ccm => Some(13),
            Self::Cbc | Self::Cfb | Self::Ofb => Some(16),
            Self::Ctr => Some(16),
            Self::Ecb => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaPkcs1v15 {
        hash: HashAlgorithm,
    },

    RsaPss {
        hash: HashAlgorithm,
        salt_len: RsaPssSaltLen,
    },

    Ecdsa {
        hash: HashAlgorithm,
    },

    Ed25519,
    Ed448,
}

/// RSA-PSS salt length options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPssSaltLen {
    /// Salt length equals hash output length (recommended).
    HashLen,
    /// Maximum possible salt length.
    Max,
    /// Specific byte length.
    Bytes(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAgreementAlgorithm {
    Ecdh,
    X25519,
    X448,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1, prime256v1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
    /// NIST P-521 (secp521r1).
    P521,
    /// Bitcoin curve.
    Secp256k1,
}

// Backward compatibility aliases
impl EcCurve {
    pub const SECP256R1: Self = Self::P256;
    pub const SECP384R1: Self = Self::P384;
    pub const SECP521R1: Self = Self::P521;
}

//
// ============================================================
// Generic Streaming Context
// ============================================================
//

/// Base trait for all streaming cryptographic operations.
///
/// Follows the init → update → finish pattern for memory-efficient
/// processing of arbitrarily large data.
pub trait StreamingContext: Send {
    /// Feed data into the context. Can be called multiple times.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()>;
}

//
// ============================================================
// Hash API
// ============================================================
//

pub trait HashContext: StreamingContext {
    /// Finalize and return the hash digest.
    fn finish(self: Box<Self>) -> CryptoResult<Vec<u8>>;

    /// Returns the output size in bytes.
    fn output_size(&self) -> usize;
}

//
// ============================================================
// MAC API
// ============================================================
//

pub trait MacContext: StreamingContext {
    /// Finalize and return the MAC tag.
    fn finish(self: Box<Self>) -> CryptoResult<Vec<u8>>;

    /// Verify MAC against expected value using constant-time comparison.
    ///
    /// Implementations MUST use constant-time comparison to prevent
    /// timing attacks.
    fn verify(self: Box<Self>, expected: &[u8])
        -> CryptoResult<bool>;

    /// Returns the output size in bytes.
    fn output_size(&self) -> usize;
}

//
// ============================================================
// Cipher API
// ============================================================
//

#[derive(Debug, Clone)]
pub struct CipherParams<'a> {
    pub algorithm: CipherAlgorithm,

    /// Initialization vector / nonce.
    pub iv: Option<&'a [u8]>,

    //
    // AEAD parameters
    //

    /// Additional authenticated data (AEAD modes only).
    pub aad: Option<&'a [u8]>,

    /// Authentication tag length in bytes (AEAD modes only).
    /// Defaults to 16 (128 bits) if not specified.
    pub tag_len: Option<usize>,
}

impl<'a> CipherParams<'a> {
    /// Create parameters for AES-CBC encryption/decryption.
    pub fn aes_cbc(iv: &'a [u8]) -> Self {
        Self {
            algorithm: CipherAlgorithm::Aes(CipherMode::Cbc),
            iv: Some(iv),
            aad: None,
            tag_len: None,
        }
    }

    /// Create parameters for AES-GCM encryption.
    pub fn aes_gcm(nonce: &'a [u8]) -> Self {
        Self {
            algorithm: CipherAlgorithm::Aes(CipherMode::Gcm),
            iv: Some(nonce),
            aad: None,
            tag_len: Some(16),
        }
    }

    /// Create parameters for AES-GCM with AAD.
    pub fn aes_gcm_with_aad(nonce: &'a [u8], aad: &'a [u8]) -> Self {
        Self {
            algorithm: CipherAlgorithm::Aes(CipherMode::Gcm),
            iv: Some(nonce),
            aad: Some(aad),
            tag_len: Some(16),
        }
    }
}

/// Result of AEAD encryption containing ciphertext and authentication tag.
#[derive(Debug, Clone)]
pub struct AeadOutput {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

pub trait CipherContext: Send {
    /// Process input data and append to output buffer.
    fn update(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> CryptoResult<()>;

    /// Finalize encryption/decryption.
    ///
    /// For AEAD decryption, this verifies the authentication tag
    /// and returns `TagMismatch` error if verification fails.
    ///
    /// Returns the authentication tag for AEAD encryption.
    fn finish(
        self: Box<Self>,
        output: &mut Vec<u8>,
    ) -> CryptoResult<Option<Vec<u8>>>;

    /// Set the expected authentication tag for AEAD decryption.
    ///
    /// Must be called before `finish()` for AEAD decryption.
    fn set_tag(&mut self, tag: &[u8]) -> CryptoResult<()>;

    /// Returns true if this context uses AEAD mode.
    fn is_aead(&self) -> bool;
}

//
// ============================================================
// Signature API
// ============================================================
//

#[derive(Debug, Clone)]
pub struct SignatureParams {
    pub algorithm: SignatureAlgorithm,
}

pub trait SignContext: StreamingContext {
    /// Finalize and produce the signature.
    fn finish(self: Box<Self>) -> CryptoResult<Vec<u8>>;
}

pub trait VerifyContext: StreamingContext {
    /// Verify the signature against the accumulated message.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid signature format
    /// but valid operation, or `Err(AuthenticationFailed)` for invalid signature.
    fn finish(self: Box<Self>, signature: &[u8])
        -> CryptoResult<bool>;
}

//
// ============================================================
// Key Agreement API
// ============================================================
//

#[derive(Debug, Clone)]
pub struct KeyAgreementParams {
    pub algorithm: KeyAgreementAlgorithm,
}

pub trait KeyAgreementContext: Send {
    /// Derive shared secret from peer's public key.
    ///
    /// The returned shared secret should typically be passed through
    /// a KDF before use as key material.
    fn derive(
        self: Box<Self>,
        peer_public_key: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

//
// ============================================================
// Random API
// ============================================================
//

pub trait RandomGenerator: Send + Sync {
    /// Fill the buffer with cryptographically secure random bytes.
    fn fill(&mut self, output: &mut [u8]) -> CryptoResult<()>;

    /// Generate a specific number of random bytes.
    fn generate(&mut self, len: usize) -> CryptoResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.fill(&mut buf)?;
        Ok(buf)
    }

    /// Generate a random u32.
    fn u32(&mut self) -> CryptoResult<u32> {
        let mut buf = [0u8; 4];
        self.fill(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Generate a random u64.
    fn u64(&mut self) -> CryptoResult<u64> {
        let mut buf = [0u8; 8];
        self.fill(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Generate a random value in range [0, max).
    fn u32_range(&mut self, max: u32) -> CryptoResult<u32> {
        if max == 0 {
            return Err(CryptoError::invalid_input("max must be > 0"));
        }
        // Simple rejection sampling (implementations may optimize)
        loop {
            let val = self.u32()?;
            // Avoid modulo bias
            let threshold = u32::MAX - (u32::MAX % max);
            if val < threshold {
                return Ok(val % max);
            }
        }
    }
}






//
// ============================================================
// Example Usage
// ============================================================
//

// ----------------------------------------------------------------
// Creating and Finding Keys
// ----------------------------------------------------------------
/*
fn example_key_management<P: CryptoProvider>(provider: &P)
    -> CryptoResult<KeyHandle>
{
    // Create a new AES-256 key with a label
    let key = provider.create_key(
        CreateKeyParams::symmetric_256()
            .with_label("my-encryption-key")
    )?;

    // Get key info
    let info = provider.key_info(&key)?;
    println!("Created key: {:?}", info.algorithm);

    // Find the key later by exact label
    let found = provider.find_key(KeyQuery::by_label("my-encryption-key"))?;

    Ok(key)
}
*/
// ----------------------------------------------------------------
// HMAC (Streaming)
// ----------------------------------------------------------------

fn example_hmac<P: CryptoProvider>(provider: &P, key: &KeyHandle)
    -> CryptoResult<Vec<u8>>
{
    let mut ctx = provider.hmac(
        MacAlgorithm::Hmac(HashAlgorithm::Sha256),
        key,
    )?;

    ctx.update(b"hello ")?;
    ctx.update(b"world")?;

    ctx.finish()
}

// ----------------------------------------------------------------
// Key Derivation (HKDF)
// ----------------------------------------------------------------

fn example_hkdf<P: CryptoProvider>(provider: &P)
    -> CryptoResult<Vec<u8>>
{
    let params = KdfParams {
        key_handle: KeyHandle::new(1), // Example key handle
        algorithm: KdfAlgorithm::Hkdf(HashAlgorithm::Sha256),
        ikm: b"input key material",
        //key: b"psk handle",
        salt: Some(b"optional salt"),
        info: Some(b"context info"),
        output_len: 32,
    };

    provider.derive_key(params)
}

// ----------------------------------------------------------------
// AES-GCM Encrypt
// ----------------------------------------------------------------

fn example_gcm_encrypt<P: CryptoProvider>(
    provider: &P,
    key: &KeyHandle,
) -> CryptoResult<AeadOutput>
{
    // Using the convenience constructor
    let params = CipherParams::aes_gcm_with_aad(&[0u8; 12], b"header");

    let mut ctx = provider.cipher_encrypt(params, key)?;

    let mut ciphertext = Vec::new();

    ctx.update(b"plaintext", &mut ciphertext)?;

    // finish() now returns the tag for AEAD modes
    let tag = ctx.finish(&mut ciphertext)?
        .expect("AEAD encryption must return tag");

    Ok(AeadOutput { ciphertext, tag })
}

// ----------------------------------------------------------------
// AES-GCM Decrypt
// ----------------------------------------------------------------

fn example_gcm_decrypt<P: CryptoProvider>(
    provider: &P,
    key: &KeyHandle,
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>>
{
    let params = CipherParams {
        algorithm: CipherAlgorithm::Aes(CipherMode::Gcm),
        iv: Some(&[0u8; 12]),
        aad: Some(aad),
        tag_len: Some(16),
    };

    let mut ctx = provider.cipher_decrypt(params, key)?;

    // Set the expected tag before finishing
    ctx.set_tag(tag)?;

    let mut plaintext = Vec::new();
    ctx.update(ciphertext, &mut plaintext)?;

    // finish() will verify the tag and return TagMismatch error if invalid
    ctx.finish(&mut plaintext)?;

    Ok(plaintext)
}

// ----------------------------------------------------------------
// ECDSA Sign
// ----------------------------------------------------------------

fn example_ecdsa<P: CryptoProvider>(
    provider: &P,
    key: &KeyHandle,
) -> CryptoResult<Vec<u8>>
{
    let mut signer = provider.signer(
        SignatureParams {
            algorithm: SignatureAlgorithm::Ecdsa {
                hash: HashAlgorithm::Sha256,
            },
        },
        key,
    )?;

    signer.update(b"message")?;

    signer.finish()
}

// ----------------------------------------------------------------
// ECDH
// ----------------------------------------------------------------

fn example_ecdh<P: CryptoProvider>(
    provider: &P,
    private_key: &KeyHandle,
    peer_public: &[u8],
) -> CryptoResult<Vec<u8>>
{
    let ka = provider.key_agreement(
        KeyAgreementParams {
            algorithm: KeyAgreementAlgorithm::Ecdh,
        },
        private_key,
    )?;

    ka.derive(peer_public)
}