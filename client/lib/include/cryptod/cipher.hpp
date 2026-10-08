#pragma once

#include <memory>
#include <vector>
#include <cstdint>
#include <span>
#include <optional>

#include "cryptod/algorithm.hpp"
#include "cryptod/key.hpp"

namespace cryptod {

// Forward declaration
class Client;

/// Parameters for cipher operations.
struct CipherParams {
    CipherMode mode;
    std::vector<uint8_t> iv;            // IV/nonce
    std::vector<uint8_t> aad;           // Additional authenticated data (AEAD only)
    std::optional<uint32_t> tag_len;    // Tag length for AEAD (default: 16)

    /// Create params for AES-CBC.
    static CipherParams aes_cbc(std::span<const uint8_t> iv) {
        CipherParams p;
        p.mode = CipherMode::Cbc;
        p.iv.assign(iv.begin(), iv.end());
        return p;
    }

    /// Create params for AES-GCM.
    static CipherParams aes_gcm(std::span<const uint8_t> nonce) {
        CipherParams p;
        p.mode = CipherMode::Gcm;
        p.iv.assign(nonce.begin(), nonce.end());
        p.tag_len = 16;
        return p;
    }

    /// Create params for AES-GCM with AAD.
    static CipherParams aes_gcm_with_aad(
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> aad
    ) {
        CipherParams p;
        p.mode = CipherMode::Gcm;
        p.iv.assign(nonce.begin(), nonce.end());
        p.aad.assign(aad.begin(), aad.end());
        p.tag_len = 16;
        return p;
    }
};

/// Streaming cipher context.
class CipherContext {
public:
    virtual ~CipherContext() = default;

    /// Process input data.
    /// For block ciphers, may not produce output until enough data is accumulated.
    virtual std::vector<uint8_t> update(std::span<const uint8_t> input) = 0;

    /// Set the expected authentication tag (AEAD decryption only).
    /// Must be called before finish() for AEAD decryption.
    virtual void set_tag(std::span<const uint8_t> tag) = 0;

    /// Finalize the cipher operation.
    /// Returns remaining output and (for AEAD encryption) the authentication tag.
    virtual std::vector<uint8_t> finish() = 0;

    /// Get the authentication tag after finish() (AEAD encryption only).
    virtual std::optional<std::vector<uint8_t>> get_tag() const = 0;

    /// Check if this cipher uses AEAD mode.
    virtual bool is_aead() const = 0;

protected:
    CipherContext() = default;
};

/// Implementation class for CipherContext (used internally)
class CipherContextImpl : public CipherContext {
public:
    CipherContextImpl(int fd, uint64_t handle, bool encrypting, bool is_aead);
    ~CipherContextImpl() override;
    std::vector<uint8_t> update(std::span<const uint8_t> input) override;
    void set_tag(std::span<const uint8_t> tag) override;
    std::vector<uint8_t> finish() override;
    std::optional<std::vector<uint8_t>> get_tag() const override;
    bool is_aead() const override;

private:
    int fd_;
    uint64_t handle_;
    bool encrypting_;
    bool is_aead_;
    bool finished_;
    std::optional<std::vector<uint8_t>> tag_;
};

} // namespace cryptod
