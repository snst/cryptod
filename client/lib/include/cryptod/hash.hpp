#pragma once

#include <memory>
#include <vector>
#include <cstdint>
#include <span>

#include "cryptod/algorithm.hpp"

namespace cryptod {

// Forward declaration
class Client;

/// Streaming hash context.
class HashContext {
public:
    virtual ~HashContext() = default;

    /// Update the hash with additional data.
    virtual void update(std::span<const uint8_t> data) = 0;

    /// Convenience overload for string data.
    void update(const std::string& data) {
        update(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()), 
            data.size()
        ));
    }

    /// Finalize and return the hash digest.
    /// After calling finish(), the context is invalid.
    virtual std::vector<uint8_t> finish() = 0;

    /// Get the output size of this hash algorithm in bytes.
    virtual size_t output_size() const = 0;

protected:
    HashContext() = default;
};

/// Implementation class for HashContext (used internally)
class HashContextImpl : public HashContext {
public:
    HashContextImpl(int fd, uint64_t handle, uint32_t output_size);
    ~HashContextImpl() override;
    void update(std::span<const uint8_t> data) override;
    std::vector<uint8_t> finish() override;
    size_t output_size() const override;

private:
    int fd_;
    uint64_t handle_;
    uint32_t output_size_;
    bool finished_;
};

} // namespace cryptod
