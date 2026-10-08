//! Native Rust backend implementation for cryptographic operations.
//!
//! This backend uses pure Rust crates for cryptographic primitives:
//! - `sha2` for SHA-256/384 hashing
//! - `hmac` for HMAC operations
//! - `getrandom` for secure random number generation
//!
//! # Supported Operations
//!
//! - Hash: SHA-256, SHA-384
//! - HMAC: HMAC-SHA256, HMAC-SHA384
//! - Random: Cryptographically secure random bytes
//!
//! # Example
//!
//! ```
//! use crypto_native::NativeProvider;
//! use crypto_api::{CryptoProvider, CreateKeyParams, HashAlgorithm, MacAlgorithm};
//!
//! let provider = NativeProvider::new();
//!
//! // Create a key
//! let key = provider.create_key(CreateKeyParams::symmetric_256()).unwrap();
//! ```

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    RwLock,
};

use aes::Aes128;
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crypto_api::{
    CipherAlgorithm, CipherContext, CipherMode, CipherParams, CreateKeyParams, CryptoError,
    CryptoProvider, CryptoResult, HashAlgorithm, HashContext, ImportKeyParams, KdfAlgorithm,
    KdfParams, KeyAgreementContext, KeyAgreementParams, KeyAlgorithm, KeyBackendKind, KeyFormat,
    KeyHandle, KeyId, KeyInfo, KeyQuery, KeyWrapParams, MacAlgorithm, MacContext,
    ProviderCapabilities, RandomGenerator, SignContext, SignatureParams, StreamingContext,
    SymmetricKeySize, VerifyContext,
};

// Type aliases for HMAC variants
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

// Type aliases for AES-CBC variants
type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

// ============================================================
// Native Provider
// ============================================================

/// Native Rust cryptographic provider.
///
/// Implements cryptographic operations using pure Rust crates.
/// Keys are stored internally and accessed via handles.
///
/// Currently supports:
/// - Hashing: SHA-256, SHA-384
/// - MAC: HMAC-SHA256, HMAC-SHA384
/// - Random: CSPRNG via `getrandom`
pub struct NativeProvider {
    /// Internal key storage: key ID -> NativeKey
    keys: RwLock<HashMap<KeyId, NativeKey>>,
    /// Counter for generating unique key IDs
    next_id: AtomicU64,
}

impl std::fmt::Debug for NativeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeProvider")
            .field("key_count", &self.keys.read().map(|k| k.len()).unwrap_or(0))
            .finish()
    }
}

impl Clone for NativeProvider {
    fn clone(&self) -> Self {
        Self {
            keys: RwLock::new(self.keys.read().unwrap().clone()),
            next_id: AtomicU64::new(self.next_id.load(Ordering::SeqCst)),
        }
    }
}

impl Default for NativeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeProvider {
    /// Create a new native provider instance.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Generate the next unique key ID.
    fn next_key_id(&self) -> KeyId {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Get a key by its handle.
    fn get_key(&self, handle: &KeyHandle) -> CryptoResult<NativeKey> {
        let keys = self
            .keys
            .read()
            .map_err(|_| CryptoError::backend_error("Lock poisoned"))?;
        keys.get(&handle.id())
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(handle.to_string()))
    }

    /// Store a key and return its handle.
    fn store_key(&self, mut key: NativeKey) -> CryptoResult<KeyHandle> {
        // Always generate a unique numeric ID
        let key_id = self.next_key_id();

        let mut keys = self
            .keys
            .write()
            .map_err(|_| CryptoError::backend_error("Lock poisoned"))?;

        // Check for duplicate labels
        if keys.values().any(|k| k.info.label == key.info.label) {
            return Err(CryptoError::invalid_input(format!(
                "Key with label '{}' already exists",
                key.info.label
            )));
        }

        // Store the generated ID in the key info
        key.info.id = Some(key_id);
        keys.insert(key_id, key);

        Ok(KeyHandle::new(key_id))
    }
}

impl CryptoProvider for NativeProvider {
    fn name(&self) -> &str {
        "native-rust"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            algorithms: vec![
                KeyAlgorithm::Symmetric, // Generic symmetric keys
                KeyAlgorithm::Aes(SymmetricKeySize::Bits128),
                KeyAlgorithm::Aes(SymmetricKeySize::Bits192),
                KeyAlgorithm::Aes(SymmetricKeySize::Bits256),
                KeyAlgorithm::Hmac(HashAlgorithm::Sha256),
                KeyAlgorithm::Hmac(HashAlgorithm::Sha384),
                KeyAlgorithm::Cmac,
            ],
            hash_algorithms: vec![HashAlgorithm::Sha256, HashAlgorithm::Sha384],
            cipher_modes: vec![CipherMode::Cbc],
            signature_algorithms: vec![], // Not implemented yet
        }
    }

    // --------------------------------------------------------
    // Key Management
    // --------------------------------------------------------

    fn create_key(&self, params: CreateKeyParams) -> CryptoResult<KeyHandle> {
        // Check if this is a symmetric key algorithm
        if !params.algorithm.is_symmetric() {
            return Err(CryptoError::invalid_algorithm(format!(
                "{:?} - only symmetric keys supported",
                params.algorithm
            )));
        }

        // For symmetric keys, size must be specified
        let size_bits = match params.size_bits {
            Some(bits) => bits,
            None => {
                return Err(CryptoError::invalid_input(
                    "size_bits required for symmetric key generation",
                ));
            }
        };

        // Validate key size
        if size_bits % 8 != 0 || size_bits < 128 {
            return Err(CryptoError::invalid_input(format!(
                "Invalid key size: {} bits",
                size_bits
            )));
        }

        let key_len = size_bits / 8;
        let mut material = vec![0u8; key_len];
        getrandom::getrandom(&mut material).map_err(|_| CryptoError::EntropyUnavailable)?;

        let key = NativeKey {
            info: KeyInfo {
                id: None, // Will be auto-generated by store_key
                label: params.label,
                algorithm: params.algorithm,
                usage: params.usage,
                extractable: params.extractable,
                backend: KeyBackendKind::Software,
                size_bits: Some(size_bits),
            },
            material,
        };

        self.store_key(key)
    }

    fn import_key(&self, params: ImportKeyParams) -> CryptoResult<KeyHandle> {
        use crypto_api::KeyMaterial;

        // Only symmetric keys supported for now
        if !params.algorithm.is_symmetric() {
            return Err(CryptoError::unsupported(format!(
                "{:?} - only symmetric keys supported",
                params.algorithm
            )));
        }

        match params.material {
            KeyMaterial::Plaintext(data) => {
                let size_bits = data.len() * 8;

                let key = NativeKey {
                    info: KeyInfo {
                        id: None, // Will be auto-generated by store_key
                        label: params.label,
                        algorithm: params.algorithm,
                        usage: params.usage,
                        extractable: params.extractable,
                        backend: KeyBackendKind::Software,
                        size_bits: Some(size_bits),
                    },
                    material: data.to_vec(),
                };

                self.store_key(key)
            }
            _ => Err(CryptoError::unsupported(
                "Only plaintext key import is supported",
            )),
        }
    }

    fn key_info(&self, key: &KeyHandle) -> CryptoResult<KeyInfo> {
        let native_key = self.get_key(key)?;
        Ok(native_key.info)
    }

    fn find_key(&self, query: KeyQuery) -> CryptoResult<Option<KeyHandle>> {
        let query_label = query.label;

        let keys = self
            .keys
            .read()
            .map_err(|_| CryptoError::backend_error("Lock poisoned"))?;

        let mut matches = keys.iter().filter(|(_, key)| key.info.label == query_label);

        let first = matches.next().map(|(id, _)| KeyHandle::new(*id));

        if matches.next().is_some() {
            return Err(CryptoError::backend_error(format!(
                "Multiple keys found with label '{}'",
                query_label
            )));
        }

        Ok(first)
    }

    fn export_key(&self, key: &KeyHandle, format: KeyFormat) -> CryptoResult<Vec<u8>> {
        let native_key = self.get_key(key)?;

        if !native_key.info.extractable {
            return Err(CryptoError::UsageNotPermitted("export".into()));
        }

        match format {
            KeyFormat::Raw => Ok(native_key.material),
            _ => Err(CryptoError::unsupported(format!(
                "Export format {:?}",
                format
            ))),
        }
    }

    fn delete_key(&self, handle: &KeyHandle) -> CryptoResult<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| CryptoError::backend_error("Lock poisoned"))?;

        if keys.remove(&handle.id()).is_some() {
            Ok(())
        } else {
            Err(CryptoError::KeyNotFound(handle.to_string()))
        }
    }

    fn wrap_key(
        &self,
        _key_to_wrap: &KeyHandle,
        _wrapping_key: &KeyHandle,
        _params: KeyWrapParams,
    ) -> CryptoResult<Vec<u8>> {
        Err(CryptoError::unsupported("Key wrapping not implemented"))
    }

    fn unwrap_key(
        &self,
        _wrapped_key: &[u8],
        _unwrapping_key: &KeyHandle,
        _params: KeyWrapParams,
    ) -> CryptoResult<KeyHandle> {
        Err(CryptoError::unsupported("Key unwrapping not implemented"))
    }

    // --------------------------------------------------------
    // Hash Operations
    // --------------------------------------------------------

    fn hash(&self, algorithm: HashAlgorithm) -> CryptoResult<Box<dyn HashContext>> {
        match algorithm {
            HashAlgorithm::Sha256 => Ok(Box::new(NativeHashContext::Sha256(Sha256::new()))),
            HashAlgorithm::Sha384 => Ok(Box::new(NativeHashContext::Sha384(Sha384::new()))),
            _ => Err(CryptoError::invalid_algorithm(format!("{:?}", algorithm))),
        }
    }

    // --------------------------------------------------------
    // HMAC Operations
    // --------------------------------------------------------

    fn hmac(&self, algorithm: MacAlgorithm, key: &KeyHandle) -> CryptoResult<Box<dyn MacContext>> {
        let native_key = self.get_key(key)?;

        match algorithm {
            MacAlgorithm::Hmac(HashAlgorithm::Sha256) => {
                let mac = HmacSha256::new_from_slice(&native_key.material)
                    .map_err(|_| CryptoError::invalid_key("Invalid HMAC key length"))?;
                Ok(Box::new(NativeMacContext::HmacSha256 {
                    mac,
                    //key: native_key.material,
                }))
            }
            MacAlgorithm::Hmac(HashAlgorithm::Sha384) => {
                let mac = HmacSha384::new_from_slice(&native_key.material)
                    .map_err(|_| CryptoError::invalid_key("Invalid HMAC key length"))?;
                Ok(Box::new(NativeMacContext::HmacSha384 {
                    mac,
                    //key: native_key.material,
                }))
            }
            _ => Err(CryptoError::invalid_algorithm(format!("{:?}", algorithm))),
        }
    }

    // --------------------------------------------------------
    // Cipher Operations
    // --------------------------------------------------------

    fn cipher_encrypt(
        &self,
        params: CipherParams,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn CipherContext>> {
        let native_key = self.get_key(key)?;

        match params.algorithm {
            CipherAlgorithm::Aes(CipherMode::Cbc) => {
                let iv = params.iv.ok_or_else(|| CryptoError::InvalidNonce {
                    expected_len: 16,
                    actual_len: 0,
                })?;

                if iv.len() != 16 {
                    return Err(CryptoError::InvalidNonce {
                        expected_len: 16,
                        actual_len: iv.len(),
                    });
                }

                let iv_array: [u8; 16] = iv.try_into().map_err(|_| CryptoError::InvalidNonce {
                    expected_len: 16,
                    actual_len: iv.len(),
                })?;

                match native_key.material.len() {
                    16 => {
                        let key_array: [u8; 16] =
                            native_key.material.as_slice().try_into().map_err(|_| {
                                CryptoError::invalid_key("Invalid AES-128 key length")
                            })?;
                        let cipher = Aes128CbcEnc::new(&key_array.into(), &iv_array.into());
                        Ok(Box::new(NativeCipherContext::Aes128CbcEncrypt {
                            cipher,
                            buffer: Vec::new(),
                        }))
                    }
                    32 => {
                        let key_array: [u8; 32] =
                            native_key.material.as_slice().try_into().map_err(|_| {
                                CryptoError::invalid_key("Invalid AES-256 key length")
                            })?;
                        let cipher = Aes256CbcEnc::new(&key_array.into(), &iv_array.into());
                        Ok(Box::new(NativeCipherContext::Aes256CbcEncrypt {
                            cipher,
                            buffer: Vec::new(),
                        }))
                    }
                    len => Err(CryptoError::invalid_key(format!(
                        "AES key must be 16 or 32 bytes, got {}",
                        len
                    ))),
                }
            }
            _ => Err(CryptoError::unsupported(format!(
                "Cipher mode {:?} not implemented",
                params.algorithm
            ))),
        }
    }

    fn cipher_decrypt(
        &self,
        params: CipherParams,
        key: &KeyHandle,
    ) -> CryptoResult<Box<dyn CipherContext>> {
        let native_key = self.get_key(key)?;

        match params.algorithm {
            CipherAlgorithm::Aes(CipherMode::Cbc) => {
                let iv = params.iv.ok_or_else(|| CryptoError::InvalidNonce {
                    expected_len: 16,
                    actual_len: 0,
                })?;

                if iv.len() != 16 {
                    return Err(CryptoError::InvalidNonce {
                        expected_len: 16,
                        actual_len: iv.len(),
                    });
                }

                let iv_array: [u8; 16] = iv.try_into().map_err(|_| CryptoError::InvalidNonce {
                    expected_len: 16,
                    actual_len: iv.len(),
                })?;

                match native_key.material.len() {
                    16 => {
                        let key_array: [u8; 16] =
                            native_key.material.as_slice().try_into().map_err(|_| {
                                CryptoError::invalid_key("Invalid AES-128 key length")
                            })?;
                        let cipher = Aes128CbcDec::new(&key_array.into(), &iv_array.into());
                        Ok(Box::new(NativeCipherContext::Aes128CbcDecrypt {
                            cipher,
                            buffer: Vec::new(),
                        }))
                    }
                    32 => {
                        let key_array: [u8; 32] =
                            native_key.material.as_slice().try_into().map_err(|_| {
                                CryptoError::invalid_key("Invalid AES-256 key length")
                            })?;
                        let cipher = Aes256CbcDec::new(&key_array.into(), &iv_array.into());
                        Ok(Box::new(NativeCipherContext::Aes256CbcDecrypt {
                            cipher,
                            buffer: Vec::new(),
                        }))
                    }
                    len => Err(CryptoError::invalid_key(format!(
                        "AES key must be 16 or 32 bytes, got {}",
                        len
                    ))),
                }
            }
            _ => Err(CryptoError::unsupported(format!(
                "Cipher mode {:?} not implemented",
                params.algorithm
            ))),
        }
    }

    // --------------------------------------------------------
    // Signature Operations (not implemented)
    // --------------------------------------------------------

    fn signer(
        &self,
        _params: SignatureParams,
        _key: &KeyHandle,
    ) -> CryptoResult<Box<dyn SignContext>> {
        Err(CryptoError::unsupported(
            "Signature operations not implemented",
        ))
    }

    fn verifier(
        &self,
        _params: SignatureParams,
        _key: &KeyHandle,
    ) -> CryptoResult<Box<dyn VerifyContext>> {
        Err(CryptoError::unsupported(
            "Signature operations not implemented",
        ))
    }

    // --------------------------------------------------------
    // Key Agreement (not implemented)
    // --------------------------------------------------------

    fn key_agreement(
        &self,
        _params: KeyAgreementParams,
        _private_key: &KeyHandle,
    ) -> CryptoResult<Box<dyn KeyAgreementContext>> {
        Err(CryptoError::unsupported("Key agreement not implemented"))
    }

    // --------------------------------------------------------
    // Random Number Generation
    // --------------------------------------------------------

    fn random(&self) -> CryptoResult<Box<dyn RandomGenerator>> {
        Ok(Box::new(NativeRandomGenerator))
    }

    // --------------------------------------------------------
    // Key Derivation
    // --------------------------------------------------------

    fn derive_key(&self, params: KdfParams) -> CryptoResult<Vec<u8>> {
        match params.algorithm {
            KdfAlgorithm::Tls12Prf(prf_params) => {
                let key_material = match self.export_key(&params.key_handle, KeyFormat::Raw) {
                    Ok(material) => material,
                    Err(e) => return Err(e),
                };

                let mut ikm = vec![0u8; 4 + (2 * key_material.len())];
                let key_len = key_material.len();
                let key_dest = key_len + 4;
                ikm[0] = (key_len >> 8) as u8;
                ikm[1] = (key_len & 0xff) as u8;
                ikm[key_len + 2] = ikm[0];
                ikm[key_len + 3] = ikm[1];
                ikm[key_dest..].copy_from_slice(&key_material);

                // Build the seed: label + info (typically client_random + server_random)
                let label = prf_params.label.as_bytes();
                let info = params.info.unwrap_or(&[]);
                let mut seed = Vec::with_capacity(label.len() + info.len());
                seed.extend_from_slice(label);
                seed.extend_from_slice(info);

                tls12_prf(prf_params.hash, &ikm, &seed, params.output_len)
            }
            KdfAlgorithm::Hkdf(_hash) => {
                Err(CryptoError::unsupported("HKDF not implemented"))
                // hkdf_expand_extract(
                //     hash,
                //     params.ikm,
                //     params.salt.unwrap_or(&[]),
                //     params.info.unwrap_or(&[]),
                //     params.output_len,
                // )
            }
            KdfAlgorithm::Pbkdf2(_) => Err(CryptoError::unsupported("PBKDF2 not implemented")),
        }
    }
}

// ============================================================
// TLS 1.2 PRF Implementation (RFC 5246)
// ============================================================

/// TLS 1.2 PRF: PRF(secret, label, seed) = P_<hash>(secret, label + seed)
///
/// P_hash is defined as:
///   P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                          HMAC_hash(secret, A(2) + seed) +
///                          HMAC_hash(secret, A(3) + seed) + ...
/// where:
///   A(0) = seed
///   A(i) = HMAC_hash(secret, A(i-1))
fn tls12_prf(
    hash: HashAlgorithm,
    secret: &[u8],
    seed: &[u8],
    output_len: usize,
) -> CryptoResult<Vec<u8>> {
    match hash {
        HashAlgorithm::Sha256 => p_hash_sha256(secret, seed, output_len),
        HashAlgorithm::Sha384 => p_hash_sha384(secret, seed, output_len),
        _ => Err(CryptoError::invalid_algorithm(format!(
            "TLS 1.2 PRF does not support {:?}",
            hash
        ))),
    }
}

/// P_hash function for SHA-256.
fn p_hash_sha256(secret: &[u8], seed: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let mut result = Vec::with_capacity(output_len);

    // A(0) = seed
    // A(i) = HMAC_hash(secret, A(i-1))
    let mut a = hmac_sha256(secret, seed)?;

    while result.len() < output_len {
        // HMAC_hash(secret, A(i) + seed)
        let mut a_plus_seed = Vec::with_capacity(a.len() + seed.len());
        a_plus_seed.extend_from_slice(&a);
        a_plus_seed.extend_from_slice(seed);

        let p_block = hmac_sha256(secret, &a_plus_seed)?;
        result.extend_from_slice(&p_block);

        // A(i+1) = HMAC_hash(secret, A(i))
        a = hmac_sha256(secret, &a)?;
    }

    result.truncate(output_len);
    Ok(result)
}

/// P_hash function for SHA-384.
fn p_hash_sha384(secret: &[u8], seed: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let mut result = Vec::with_capacity(output_len);

    let mut a = hmac_sha384(secret, seed)?;

    while result.len() < output_len {
        let mut a_plus_seed = Vec::with_capacity(a.len() + seed.len());
        a_plus_seed.extend_from_slice(&a);
        a_plus_seed.extend_from_slice(seed);

        let p_block = hmac_sha384(secret, &a_plus_seed)?;
        result.extend_from_slice(&p_block);

        a = hmac_sha384(secret, &a)?;
    }

    result.truncate(output_len);
    Ok(result)
}

/// Compute HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| CryptoError::invalid_key("Invalid HMAC key length"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Compute HMAC-SHA384.
fn hmac_sha384(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut mac = HmacSha384::new_from_slice(key)
        .map_err(|_| CryptoError::invalid_key("Invalid HMAC key length"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ============================================================
// HKDF Implementation (RFC 5869)
// ============================================================

// /// HKDF extract and expand.
// fn hkdf_expand_extract(
//     hash: HashAlgorithm,
//     ikm: &[u8],
//     salt: &[u8],
//     info: &[u8],
//     output_len: usize,
// ) -> CryptoResult<Vec<u8>> {
//     match hash {
//         HashAlgorithm::Sha256 => hkdf_sha256(ikm, salt, info, output_len),
//         HashAlgorithm::Sha384 => hkdf_sha384(ikm, salt, info, output_len),
//         _ => Err(CryptoError::invalid_algorithm(format!(
//             "HKDF does not support {:?}",
//             hash
//         ))),
//     }
// }

// fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
//     const HASH_LEN: usize = 32;

//     // Extract: PRK = HMAC-Hash(salt, IKM)
//     let salt = if salt.is_empty() {
//         vec![0u8; HASH_LEN]
//     } else {
//         salt.to_vec()
//     };
//     let prk = hmac_sha256(&salt, ikm)?;

//     // Expand: OKM = T(1) | T(2) | T(3) | ...
//     let n = (output_len + HASH_LEN - 1) / HASH_LEN;
//     if n > 255 {
//         return Err(CryptoError::invalid_input("HKDF output too large"));
//     }

//     let mut okm = Vec::with_capacity(output_len);
//     let mut t = Vec::new();

//     for i in 1..=n {
//         let mut input = Vec::with_capacity(t.len() + info.len() + 1);
//         input.extend_from_slice(&t);
//         input.extend_from_slice(info);
//         input.push(i as u8);

//         t = hmac_sha256(&prk, &input)?;
//         okm.extend_from_slice(&t);
//     }

//     okm.truncate(output_len);
//     Ok(okm)
// }

// fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
//     const HASH_LEN: usize = 48;

//     let salt = if salt.is_empty() {
//         vec![0u8; HASH_LEN]
//     } else {
//         salt.to_vec()
//     };
//     let prk = hmac_sha384(&salt, ikm)?;

//     let n = (output_len + HASH_LEN - 1) / HASH_LEN;
//     if n > 255 {
//         return Err(CryptoError::invalid_input("HKDF output too large"));
//     }

//     let mut okm = Vec::with_capacity(output_len);
//     let mut t = Vec::new();

//     for i in 1..=n {
//         let mut input = Vec::with_capacity(t.len() + info.len() + 1);
//         input.extend_from_slice(&t);
//         input.extend_from_slice(info);
//         input.push(i as u8);

//         t = hmac_sha384(&prk, &input)?;
//         okm.extend_from_slice(&t);
//     }

//     okm.truncate(output_len);
//     Ok(okm)
// }

// ============================================================
// Native Key (internal storage)
// ============================================================

/// A key stored in software memory.
/// This is internal to the provider - users interact via KeyHandle.
#[derive(Debug, Clone)]
pub(crate) struct NativeKey {
    pub(crate) info: KeyInfo,
    pub(crate) material: Vec<u8>,
}

// ============================================================
// Native Hash Context
// ============================================================

/// Native hash context supporting SHA-256 and SHA-384.
enum NativeHashContext {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl StreamingContext for NativeHashContext {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        match self {
            Self::Sha256(ctx) => ctx.update(data),
            Self::Sha384(ctx) => ctx.update(data),
        }
        Ok(())
    }
}

impl HashContext for NativeHashContext {
    fn finish(self: Box<Self>) -> CryptoResult<Vec<u8>> {
        Ok(match *self {
            Self::Sha256(ctx) => ctx.finalize().to_vec(),
            Self::Sha384(ctx) => ctx.finalize().to_vec(),
        })
    }

    fn output_size(&self) -> usize {
        match self {
            Self::Sha256(_) => 32,
            Self::Sha384(_) => 48,
        }
    }
}

// ============================================================
// Native MAC Context
// ============================================================

/// Native MAC context supporting HMAC-SHA256 and HMAC-SHA384.
enum NativeMacContext {
    HmacSha256 { mac: HmacSha256/*, key: Vec<u8> */ },
    HmacSha384 { mac: HmacSha384/*, key: Vec<u8>  */},
}

impl StreamingContext for NativeMacContext {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        match self {
            Self::HmacSha256 { mac, .. } => mac.update(data),
            Self::HmacSha384 { mac, .. } => mac.update(data),
        }
        Ok(())
    }
}

impl MacContext for NativeMacContext {
    fn finish(self: Box<Self>) -> CryptoResult<Vec<u8>> {
        Ok(match *self {
            Self::HmacSha256 { mac, .. } => mac.finalize().into_bytes().to_vec(),
            Self::HmacSha384 { mac, .. } => mac.finalize().into_bytes().to_vec(),
        })
    }

    fn verify(self: Box<Self>, expected: &[u8]) -> CryptoResult<bool> {
        // Uses constant-time comparison internally
        let result = match *self {
            Self::HmacSha256 { mac, .. } => mac.verify_slice(expected),
            Self::HmacSha384 { mac, .. } => mac.verify_slice(expected),
        };

        match result {
            Ok(()) => Ok(true),
            Err(_) => Ok(false), // Return false for tag mismatch, not error
        }
    }

    fn output_size(&self) -> usize {
        match self {
            Self::HmacSha256 { .. } => 32,
            Self::HmacSha384 { .. } => 48,
        }
    }
}

// ============================================================
// Native Random Generator
// ============================================================

/// Native random number generator using the OS CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeRandomGenerator;

impl RandomGenerator for NativeRandomGenerator {
    fn fill(&mut self, output: &mut [u8]) -> CryptoResult<()> {
        getrandom::getrandom(output).map_err(|_| CryptoError::EntropyUnavailable)
    }
}

// ============================================================
// Native Cipher Context
// ============================================================

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Native cipher context for AES-CBC encryption/decryption.
enum NativeCipherContext {
    Aes128CbcEncrypt {
        cipher: Aes128CbcEnc,
        buffer: Vec<u8>,
    },
    Aes128CbcDecrypt {
        cipher: Aes128CbcDec,
        buffer: Vec<u8>,
    },
    Aes256CbcEncrypt {
        cipher: Aes256CbcEnc,
        buffer: Vec<u8>,
    },
    Aes256CbcDecrypt {
        cipher: Aes256CbcDec,
        buffer: Vec<u8>,
    },
}

impl CipherContext for NativeCipherContext {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CryptoResult<()> {
        // Get buffer and determine if decrypting
        let (buffer, is_decrypt) = match self {
            Self::Aes128CbcEncrypt { buffer, .. } => (buffer, false),
            Self::Aes256CbcEncrypt { buffer, .. } => (buffer, false),
            Self::Aes128CbcDecrypt { buffer, .. } => (buffer, true),
            Self::Aes256CbcDecrypt { buffer, .. } => (buffer, true),
        };

        // Accumulate input data
        buffer.extend_from_slice(input);

        // Process complete blocks
        let full_blocks = buffer.len() / AES_BLOCK_SIZE;
        if full_blocks == 0 {
            return Ok(());
        }

        // For decryption, keep at least one block for padding removal
        // For encryption, we can process all complete blocks
        let blocks_to_process = if is_decrypt {
            if full_blocks > 1 {
                full_blocks - 1
            } else {
                0
            }
        } else {
            full_blocks
        };

        if blocks_to_process == 0 {
            return Ok(());
        }

        let bytes_to_process = blocks_to_process * AES_BLOCK_SIZE;
        let mut to_process: Vec<u8> = buffer.drain(..bytes_to_process).collect();

        // Now do the encryption/decryption
        match self {
            Self::Aes128CbcEncrypt { cipher, .. } => {
                cipher.encrypt_blocks_mut(to_blocks_mut(&mut to_process));
            }
            Self::Aes256CbcEncrypt { cipher, .. } => {
                cipher.encrypt_blocks_mut(to_blocks_mut(&mut to_process));
            }
            Self::Aes128CbcDecrypt { cipher, .. } => {
                cipher.decrypt_blocks_mut(to_blocks_mut(&mut to_process));
            }
            Self::Aes256CbcDecrypt { cipher, .. } => {
                cipher.decrypt_blocks_mut(to_blocks_mut(&mut to_process));
            }
        }
        output.extend_from_slice(&to_process);
        Ok(())
    }

    fn finish(self: Box<Self>, output: &mut Vec<u8>) -> CryptoResult<Option<Vec<u8>>> {
        match *self {
            Self::Aes128CbcEncrypt { mut cipher, buffer } => {
                // Apply PKCS#7 padding
                let mut padded = buffer;
                let padding_len = AES_BLOCK_SIZE - (padded.len() % AES_BLOCK_SIZE);
                padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));

                // Encrypt the final padded block(s)
                cipher.encrypt_blocks_mut(to_blocks_mut(&mut padded));
                output.extend_from_slice(&padded);
                Ok(None) // Not AEAD, no tag
            }
            Self::Aes256CbcEncrypt { mut cipher, buffer } => {
                let mut padded = buffer;
                let padding_len = AES_BLOCK_SIZE - (padded.len() % AES_BLOCK_SIZE);
                padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));

                cipher.encrypt_blocks_mut(to_blocks_mut(&mut padded));
                output.extend_from_slice(&padded);
                Ok(None)
            }
            Self::Aes128CbcDecrypt { mut cipher, buffer } => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                if buffer.len() % AES_BLOCK_SIZE != 0 {
                    return Err(CryptoError::InvalidInput(
                        "Ciphertext length must be a multiple of block size".into(),
                    ));
                }

                let mut data = buffer;
                cipher.decrypt_blocks_mut(to_blocks_mut(&mut data));

                // Remove PKCS#7 padding
                let padding_len = *data.last().unwrap_or(&0) as usize;
                if padding_len == 0 || padding_len > AES_BLOCK_SIZE {
                    return Err(CryptoError::InvalidInput("Invalid padding".into()));
                }
                if data.len() < padding_len {
                    return Err(CryptoError::InvalidInput("Invalid padding".into()));
                }
                // Verify padding bytes
                let padding_start = data.len() - padding_len;
                for &byte in &data[padding_start..] {
                    if byte != padding_len as u8 {
                        return Err(CryptoError::InvalidInput("Invalid padding".into()));
                    }
                }
                data.truncate(padding_start);
                output.extend_from_slice(&data);
                Ok(None)
            }
            Self::Aes256CbcDecrypt { mut cipher, buffer } => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                if buffer.len() % AES_BLOCK_SIZE != 0 {
                    return Err(CryptoError::InvalidInput(
                        "Ciphertext length must be a multiple of block size".into(),
                    ));
                }

                let mut data = buffer;
                cipher.decrypt_blocks_mut(to_blocks_mut(&mut data));

                // Remove PKCS#7 padding
                let padding_len = *data.last().unwrap_or(&0) as usize;
                if padding_len == 0 || padding_len > AES_BLOCK_SIZE {
                    return Err(CryptoError::InvalidInput("Invalid padding".into()));
                }
                if data.len() < padding_len {
                    return Err(CryptoError::InvalidInput("Invalid padding".into()));
                }
                let padding_start = data.len() - padding_len;
                for &byte in &data[padding_start..] {
                    if byte != padding_len as u8 {
                        return Err(CryptoError::InvalidInput("Invalid padding".into()));
                    }
                }
                data.truncate(padding_start);
                output.extend_from_slice(&data);
                Ok(None)
            }
        }
    }

    fn set_tag(&mut self, _tag: &[u8]) -> CryptoResult<()> {
        Err(CryptoError::unsupported(
            "CBC mode does not use authentication tags",
        ))
    }

    fn is_aead(&self) -> bool {
        false
    }
}

/// Helper function to convert a byte slice to block references.
fn to_blocks_mut(data: &mut [u8]) -> &mut [aes::Block] {
    let ptr = data.as_mut_ptr() as *mut aes::Block;
    let len = data.len() / AES_BLOCK_SIZE;
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
