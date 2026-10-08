#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <cstdint>

#include "cryptod/error.hpp"
#include "cryptod/key.hpp"
#include "cryptod/algorithm.hpp"
#include "cryptod/hash.hpp"
#include "cryptod/mac.hpp"
#include "cryptod/cipher.hpp"
#include "cryptod/kdf.hpp"

namespace cryptod {

/// Connection to the cryptod daemon.
class Client {
public:
    /// Connect to the daemon at the specified socket path.
    /// @param socket_path Path to the Unix domain socket (default: /tmp/cryptod.sock)
    /// @throws CryptoException on connection failure
    static std::unique_ptr<Client> connect(const std::string& socket_path = "/tmp/cryptod.sock");

    /// Destructor - closes the connection.
    ~Client();

    // Prevent copying
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Allow moving
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;

    // ========================================
    // Key Management
    // ========================================

    /// Create a new key with the specified parameters.
    KeyHandle create_key(const CreateKeyParams& params);

    /// Import a key from raw material.
    KeyHandle import_key(const ImportKeyParams& params);

    /// Get information about a key.
    KeyInfo get_key_info(const KeyHandle& key);

    /// Delete a key.
    void delete_key(const KeyHandle& key);

    /// Export key material (if extractable).
    std::vector<uint8_t> export_key(const KeyHandle& key, KeyFormat format = KeyFormat::Raw);

    /// Find a key matching the query.
    /// @return Key handle if found, std::nullopt otherwise.
    std::optional<KeyHandle> find_key(const FindKeyQuery& query);

    // ========================================
    // Hash Operations
    // ========================================

    /// Create a streaming hash context.
    std::unique_ptr<HashContext> hash(HashAlgorithm algorithm);

    // ========================================
    // MAC Operations
    // ========================================

    /// Create a streaming MAC context.
    std::unique_ptr<MacContext> mac(MacAlgorithm algorithm, const KeyHandle& key);

    // ========================================
    // Cipher Operations
    // ========================================

    /// Create a cipher context for encryption.
    std::unique_ptr<CipherContext> cipher_encrypt(const CipherParams& params, const KeyHandle& key);

    /// Create a cipher context for decryption.
    std::unique_ptr<CipherContext> cipher_decrypt(const CipherParams& params, const KeyHandle& key);

    // ========================================
    // Random Generation
    // ========================================

    /// Generate cryptographically secure random bytes.
    std::vector<uint8_t> generate_random(size_t length);

    // ========================================
    // Key Derivation
    // ========================================

    /// Derive key material using the specified KDF.
    /// @param params KDF parameters including algorithm, IKM, and output length
    /// @return Derived key material
    std::vector<uint8_t> derive_key(const KdfParams& params);

    /// Get the file descriptor for internal use.
    int fd() const;

private:
    Client();

    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cryptod
