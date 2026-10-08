#pragma once

#include <memory>
#include <vector>
#include <cstdint>
#include <span>

#include "cryptod/algorithm.hpp"
#include "cryptod/key.hpp"

namespace cryptod {

// Forward declaration
class Client;

/// Streaming MAC context.
class MacContext {
public:
    virtual ~MacContext() = default;

    /// Update the MAC with additional data.
    virtual void update(std::span<const uint8_t> data) = 0;
    virtual void update(const uint8_t* data, size_t len) = 0;

    /// Convenience overload for string data.
    void update(const std::string& data) {
        update(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()), 
            data.size()
        ));
    }

    /// Finalize and return the MAC tag.
    /// After calling finish(), the context is invalid.
    virtual std::vector<uint8_t> finish() = 0;

    /// Finalize and verify the MAC against an expected tag.
    /// Returns true if the tag matches.
    /// After calling verify(), the context is invalid.
    virtual bool verify(std::span<const uint8_t> expected_tag) = 0;

    /// Get the output size of this MAC algorithm in bytes.
    virtual size_t output_size() const = 0;

protected:
    MacContext() = default;
};

/// Implementation class for MacContext (used internally)
class MacContextImpl : public MacContext {
public:
    MacContextImpl(int fd, uint64_t handle, uint32_t output_size);
    ~MacContextImpl() override;
    void update(std::span<const uint8_t> data) override;
    void update(const uint8_t* data, size_t len) override;
    std::vector<uint8_t> finish() override;
    bool verify(std::span<const uint8_t> expected_tag) override;
    size_t output_size() const override;

private:
    int fd_;
    uint64_t handle_;
    uint32_t output_size_;
    bool finished_;
};

} // namespace cryptod
