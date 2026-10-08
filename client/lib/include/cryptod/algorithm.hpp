#pragma once

namespace cryptod {

/// Hash algorithms.
enum class HashAlgorithm {
    Unspecified,
    Raw,        // Pre-hashed data
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
};

/// MAC algorithms.
enum class MacAlgorithm {
    Unspecified,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha3_256,
    HmacSha3_384,
    HmacSha3_512,
    Cmac,
};

/// Cipher modes.
enum class CipherMode {
    Ecb,
    Cbc,
    Ctr,
    Cfb,
    Ofb,
    Gcm,
    Ccm,
};

/// Symmetric key sizes.
enum class SymmetricKeySize {
    Bits128 = 128,
    Bits192 = 192,
    Bits256 = 256,
    Bits384 = 384,
    Bits512 = 512,
};

/// Elliptic curves.
enum class EcCurve {
    P256,
    P384,
    P521,
    Secp256k1,
};

} // namespace cryptod
