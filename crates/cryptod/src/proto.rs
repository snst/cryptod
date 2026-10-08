//! Protocol buffer types and conversion utilities.

use prost::Message;

// Include the generated protobuf code
pub mod crypto {
    include!(concat!(env!("OUT_DIR"), "/crypto.rs"));
}

// Re-export commonly used types
pub use crypto::{
    CryptoRequest, CryptoResponse, CryptoError as ProtoError,
    ErrorCode, HashAlgorithm as ProtoHashAlgorithm,
};

use crypto_api::{
    CryptoError, HashAlgorithm, MacAlgorithm, CipherMode,
    KeyHandle, KeyUsage, KeyFormat,
};

// ============================================================
// Error Conversion
// ============================================================

impl From<CryptoError> for ProtoError {
    fn from(err: CryptoError) -> Self {
        let (code, message) = match err {
            CryptoError::InvalidKey(msg) => (ErrorCode::InvalidKey, msg),
            CryptoError::InvalidAlgorithm(msg) => (ErrorCode::InvalidAlgorithm, msg),
            CryptoError::InvalidState(msg) => (ErrorCode::InvalidState, msg),
            CryptoError::InvalidInput(msg) => (ErrorCode::InvalidInput, msg),
            CryptoError::InvalidNonce { expected_len, actual_len } => (
                ErrorCode::InvalidNonce,
                format!("expected {} bytes, got {}", expected_len, actual_len),
            ),
            CryptoError::TagMismatch => (ErrorCode::TagMismatch, "Tag mismatch".to_string()),
            CryptoError::DataTooLarge { max_size } => (
                ErrorCode::DataTooLarge,
                format!("max size: {}", max_size),
            ),
            CryptoError::AuthenticationFailed => (
                ErrorCode::AuthenticationFailed,
                "Authentication failed".to_string(),
            ),
            CryptoError::Unsupported(msg) => (ErrorCode::Unsupported, msg),
            CryptoError::BackendError { code, message } => (
                ErrorCode::BackendError,
                format!("code {}: {}", code, message),
            ),
            CryptoError::EntropyUnavailable => (
                ErrorCode::EntropyUnavailable,
                "Entropy unavailable".to_string(),
            ),
            CryptoError::BufferTooSmall { required, provided } => (
                ErrorCode::BufferTooSmall,
                format!("need {} bytes, got {}", required, provided),
            ),
            CryptoError::KeyNotFound(id) => (ErrorCode::KeyNotFound, id),
            CryptoError::KeyExpired => (ErrorCode::KeyExpired, "Key expired".to_string()),
            CryptoError::UsageNotPermitted(op) => (ErrorCode::UsageNotPermitted, op),
            CryptoError::DeviceError(msg) => (ErrorCode::DeviceError, msg),
            CryptoError::Timeout => (ErrorCode::Timeout, "Timeout".to_string()),
        };

        ProtoError {
            code: code as i32,
            message,
        }
    }
}

// ============================================================
// Algorithm Conversion (helper functions, not trait impls)
// ============================================================

/// Convert a proto HashAlgorithm value to the API HashAlgorithm.
pub fn proto_hash_to_api(value: i32) -> Result<HashAlgorithm, CryptoError> {
    match ProtoHashAlgorithm::try_from(value) {
        Ok(ProtoHashAlgorithm::Sha1) => Ok(HashAlgorithm::Sha1),
        Ok(ProtoHashAlgorithm::Sha224) => Ok(HashAlgorithm::Sha224),
        Ok(ProtoHashAlgorithm::Sha256) => Ok(HashAlgorithm::Sha256),
        Ok(ProtoHashAlgorithm::Sha384) => Ok(HashAlgorithm::Sha384),
        Ok(ProtoHashAlgorithm::Sha512) => Ok(HashAlgorithm::Sha512),
        Ok(ProtoHashAlgorithm::Sha512256) => Ok(HashAlgorithm::Sha512_256),
        Ok(ProtoHashAlgorithm::Sha3224) => Ok(HashAlgorithm::Sha3_224),
        Ok(ProtoHashAlgorithm::Sha3256) => Ok(HashAlgorithm::Sha3_256),
        Ok(ProtoHashAlgorithm::Sha3384) => Ok(HashAlgorithm::Sha3_384),
        Ok(ProtoHashAlgorithm::Sha3512) => Ok(HashAlgorithm::Sha3_512),
        Ok(ProtoHashAlgorithm::Raw) => Ok(HashAlgorithm::Raw),
        _ => Err(CryptoError::invalid_algorithm("Unknown hash algorithm")),
    }
}

/// Convert an API HashAlgorithm to proto value.
pub fn api_hash_to_proto(alg: HashAlgorithm) -> i32 {
    match alg {
        HashAlgorithm::Raw => ProtoHashAlgorithm::Raw as i32,
        HashAlgorithm::Sha1 => ProtoHashAlgorithm::Sha1 as i32,
        HashAlgorithm::Sha224 => ProtoHashAlgorithm::Sha224 as i32,
        HashAlgorithm::Sha256 => ProtoHashAlgorithm::Sha256 as i32,
        HashAlgorithm::Sha384 => ProtoHashAlgorithm::Sha384 as i32,
        HashAlgorithm::Sha512 => ProtoHashAlgorithm::Sha512 as i32,
        HashAlgorithm::Sha512_256 => ProtoHashAlgorithm::Sha512256 as i32,
        HashAlgorithm::Sha3_224 => ProtoHashAlgorithm::Sha3224 as i32,
        HashAlgorithm::Sha3_256 => ProtoHashAlgorithm::Sha3256 as i32,
        HashAlgorithm::Sha3_384 => ProtoHashAlgorithm::Sha3384 as i32,
        HashAlgorithm::Sha3_512 => ProtoHashAlgorithm::Sha3512 as i32,
    }
}

pub fn proto_mac_to_api(value: i32) -> Result<MacAlgorithm, CryptoError> {
    match crypto::MacAlgorithm::try_from(value) {
        Ok(crypto::MacAlgorithm::HmacSha1) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha1)),
        Ok(crypto::MacAlgorithm::HmacSha224) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha224)),
        Ok(crypto::MacAlgorithm::HmacSha256) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha256)),
        Ok(crypto::MacAlgorithm::HmacSha384) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha384)),
        Ok(crypto::MacAlgorithm::HmacSha512) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha512)),
        Ok(crypto::MacAlgorithm::HmacSha3256) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha3_256)),
        Ok(crypto::MacAlgorithm::HmacSha3384) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha3_384)),
        Ok(crypto::MacAlgorithm::HmacSha3512) => Ok(MacAlgorithm::Hmac(HashAlgorithm::Sha3_512)),
        Ok(crypto::MacAlgorithm::Cmac) => Ok(MacAlgorithm::Cmac),
        _ => Err(CryptoError::invalid_algorithm("Unknown MAC algorithm")),
    }
}

pub fn proto_cipher_mode_to_api(value: i32) -> Result<CipherMode, CryptoError> {
    match crypto::CipherMode::try_from(value) {
        Ok(crypto::CipherMode::Ecb) => Ok(CipherMode::Ecb),
        Ok(crypto::CipherMode::Cbc) => Ok(CipherMode::Cbc),
        Ok(crypto::CipherMode::Ctr) => Ok(CipherMode::Ctr),
        Ok(crypto::CipherMode::Cfb) => Ok(CipherMode::Cfb),
        Ok(crypto::CipherMode::Ofb) => Ok(CipherMode::Ofb),
        Ok(crypto::CipherMode::Gcm) => Ok(CipherMode::Gcm),
        Ok(crypto::CipherMode::Ccm) => Ok(CipherMode::Ccm),
        _ => Err(CryptoError::invalid_algorithm("Unknown cipher mode")),
    }
}

// ============================================================
// Key Handle Conversion
// ============================================================

impl From<&crypto::KeyHandle> for KeyHandle {
    fn from(proto: &crypto::KeyHandle) -> Self {
        KeyHandle::new(proto.id)
    }
}

impl From<&KeyHandle> for crypto::KeyHandle {
    fn from(handle: &KeyHandle) -> Self {
        crypto::KeyHandle { id: handle.id() }
    }
}

// ============================================================
// Key Usage Conversion
// ============================================================

impl From<&crypto::KeyUsage> for KeyUsage {
    fn from(proto: &crypto::KeyUsage) -> Self {
        let mut usage = KeyUsage::empty();
        if proto.encrypt { usage |= KeyUsage::ENCRYPT; }
        if proto.decrypt { usage |= KeyUsage::DECRYPT; }
        if proto.sign { usage |= KeyUsage::SIGN; }
        if proto.verify { usage |= KeyUsage::VERIFY; }
        if proto.derive { usage |= KeyUsage::DERIVE; }
        if proto.wrap { usage |= KeyUsage::WRAP; }
        if proto.unwrap { usage |= KeyUsage::UNWRAP; }
        usage
    }
}

impl From<KeyUsage> for crypto::KeyUsage {
    fn from(usage: KeyUsage) -> Self {
        crypto::KeyUsage {
            encrypt: usage.contains(KeyUsage::ENCRYPT),
            decrypt: usage.contains(KeyUsage::DECRYPT),
            sign: usage.contains(KeyUsage::SIGN),
            verify: usage.contains(KeyUsage::VERIFY),
            derive: usage.contains(KeyUsage::DERIVE),
            wrap: usage.contains(KeyUsage::WRAP),
            unwrap: usage.contains(KeyUsage::UNWRAP),
        }
    }
}

// ============================================================
// Key Format Conversion
// ============================================================

pub fn proto_key_format_to_api(value: i32) -> Result<KeyFormat, CryptoError> {
    match crypto::KeyFormat::try_from(value) {
        Ok(crypto::KeyFormat::Raw) => Ok(KeyFormat::Raw),
        Ok(crypto::KeyFormat::Pem) => Ok(KeyFormat::Pem),
        Ok(crypto::KeyFormat::Der) => Ok(KeyFormat::Der),
        Ok(crypto::KeyFormat::Pkcs8) => Ok(KeyFormat::Pkcs8),
        Ok(crypto::KeyFormat::PublicKeyOnly) => Ok(KeyFormat::PublicKeyOnly),
        _ => Err(CryptoError::invalid_input("Unknown key format")),
    }
}

// ============================================================
// Message Encoding/Decoding
// ============================================================

/// Decode a CryptoRequest from bytes.
pub fn decode_request(data: &[u8]) -> Result<CryptoRequest, CryptoError> {
    CryptoRequest::decode(data)
        .map_err(|e| CryptoError::invalid_input(format!("Failed to decode request: {}", e)))
}

/// Encode a CryptoResponse to bytes.
pub fn encode_response(response: &CryptoResponse) -> Vec<u8> {
    response.encode_to_vec()
}

/// Create an error response.
pub fn error_response(request_id: u64, error: CryptoError) -> CryptoResponse {
    CryptoResponse {
        request_id,
        error: Some(error.into()),
        response: None,
    }
}

/// Create a success response with the given payload.
pub fn success_response(request_id: u64, response: crypto::crypto_response::Response) -> CryptoResponse {
    CryptoResponse {
        request_id,
        error: None,
        response: Some(response),
    }
}
