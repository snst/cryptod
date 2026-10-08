#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace cryptod {

/// Key derivation function algorithms.
enum class KdfAlgorithm {
    Unspecified,
    /// HKDF with SHA-256.
    HkdfSha256,
    /// HKDF with SHA-384.
    HkdfSha384,
    /// HKDF with SHA-512.
    HkdfSha512,
    /// PBKDF2 with SHA-256.
    Pbkdf2Sha256,
    /// PBKDF2 with SHA-384.
    Pbkdf2Sha384,
    /// PBKDF2 with SHA-512.
    Pbkdf2Sha512,
    /// TLS 1.2 Extended Master Secret PRF with SHA-256 (RFC 7627).
    Tls12EmsPrfSha256,
    /// TLS 1.2 Extended Master Secret PRF with SHA-384 (RFC 7627).
    Tls12EmsPrfSha384,
};

/// TLS 1.2 PRF labels (RFC 5246, RFC 4279, RFC 7627).
enum class Tls12PrfLabel {
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
};

/// Parameters for key derivation.
struct KdfParams {
    /// The KDF algorithm to use.
    KdfAlgorithm algorithm;

    KeyHandle key_handle;

    /// Output length in bytes.
    size_t output_len;

    /// Salt (optional, used by HKDF and PBKDF2).
    std::optional<std::span<const uint8_t>> salt;

    /// Info/context data (for HKDF) or seed (for TLS PRF).
    std::optional<std::span<const uint8_t>> info;

    /// PRF label (for TLS 1.2 PRF only).
    std::optional<std::span<const char>> label;

    /// Iteration count (for PBKDF2 only).
    std::optional<uint32_t> iterations;
};

} // namespace cryptod
