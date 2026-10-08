#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <variant>
#include <optional>

#include "algorithm.hpp"

namespace cryptod {

/// Invalid/uninitialized key ID value.
constexpr uint64_t INVALID_KEY_ID = 0;

/// Key handle - opaque reference to a key stored in the daemon.
/// Always a numeric ID. To find a key by label, use find_key().
class KeyHandle {
public:
    /// Create a key handle from a numeric ID.
    explicit KeyHandle(uint64_t id = INVALID_KEY_ID) : id_(id) {}

    /// Get the numeric ID.
    uint64_t id() const { return id_; }

    /// Check if this handle is valid (not INVALID_KEY_ID).
    bool is_valid() const { return id_ != INVALID_KEY_ID; }

    void invalidate() { id_ = INVALID_KEY_ID; }

    bool operator==(const KeyHandle& other) const { return id_ == other.id_; }
    bool operator!=(const KeyHandle& other) const { return !(*this == other); }

private:
    uint64_t id_ = 0;
};

/// Key usage flags.
struct KeyUsage {
    bool encrypt = false;
    bool decrypt = false;
    bool sign = false;
    bool verify = false;
    bool derive = false;
    bool wrap = false;
    bool unwrap = false;

    /// Create usage flags for all operations.
    static KeyUsage all() {
        return {true, true, true, true, true, true, true};
    }

    /// Create usage flags for symmetric encryption.
    static KeyUsage symmetric() {
        return {true, true, false, false, false, false, false};
    }
};

/// Key format for import/export.
enum class KeyFormat {
    Raw = 1,
    Pem = 2,
    Der = 3,
    Pkcs8 = 4,
    PublicKeyOnly = 5,
};

/// Backend type for keys.
enum class KeyBackendKind {
    Software,
    Hsm,
    Tpm,
    Pkcs11,
    SecureElement,
    OpaqueHandle,
};

/// Information about a key.
struct KeyInfo {
    KeyHandle handle;
    std::string algorithm;  // Simplified as string for now
    KeyUsage usage;
    bool extractable;
    KeyBackendKind backend;
    std::optional<uint32_t> size_bits;
    std::optional<std::string> label;
};

/// Parameters for creating a new key.
struct CreateKeyParams {
    std::string label;
    SymmetricKeySize key_size;// = SymmetricKeySize::Bits256;
    KeyUsage usage;// = KeyUsage::all();
    bool extractable;// = true;
    CreateKeyParams(std::string label, SymmetricKeySize key_size, KeyUsage usage, bool extractable)
    : label(std::move(label)), key_size(key_size), usage(usage), extractable(extractable) {}
    /*
    /// Create params for a symmetric key.
    static CreateKeyParams symmetric(SymmetricKeySize size) {
        CreateKeyParams p;
        p.key_size = size;
        return p;
    }

    /// Create params for a 256-bit symmetric key.
    static CreateKeyParams symmetric256() {
        return symmetric(SymmetricKeySize::Bits256);
    }

    /// Create params for a 128-bit symmetric key.
    static CreateKeyParams symmetric128() {
        return symmetric(SymmetricKeySize::Bits128);
    }*/
};

/// Query for finding keys.
struct FindKeyQuery {
    std::string label;

    /// Create a query to find a key by label.
    static FindKeyQuery by_label(const std::string& label) {
        FindKeyQuery q;
        q.label = label;
        return q;
    }
};

/// Parameters for importing a key.
struct ImportKeyParams {
    std::string label;
    KeyFormat format;// = KeyFormat::Raw;
    std::vector<uint8_t> material;
    KeyUsage usage;// = KeyUsage::all();
    bool extractable;// = true;

    ImportKeyParams(std::string label, KeyFormat format, std::vector<uint8_t> material, KeyUsage usage, bool extractable)
    : label(std::move(label)), format(format), material(std::move(material)), usage(usage), extractable(extractable) {}
/*
    /// Create params for importing a symmetric key.
    static ImportKeyParams symmetric(SymmetricKeySize size, std::vector<uint8_t> material) {
        ImportKeyParams p;
        p.key_size = size;
        p.material = std::move(material);
        return p;
    }

    /// Create params for importing a symmetric key from a buffer and size.
    static ImportKeyParams symmetric(SymmetricKeySize size, const uint8_t* buffer, size_t buffer_size) {
        ImportKeyParams p;
        p.key_size = size;
        p.material = std::vector<uint8_t>(buffer, buffer + buffer_size);
        return p;
    }

    /// Create params for importing a 256-bit symmetric key.
    static ImportKeyParams symmetric256(std::vector<uint8_t> material) {
        return symmetric(SymmetricKeySize::Bits256, std::move(material));
    }

    /// Create params for importing a 128-bit symmetric key.
    static ImportKeyParams symmetric128(std::vector<uint8_t> material) {
        return symmetric(SymmetricKeySize::Bits128, std::move(material));
    }*/
};

} // namespace cryptod
