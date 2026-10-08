#pragma once

#include <stdexcept>
#include <string>

namespace cryptod {

/// Error codes matching the protocol definition.
enum class ErrorCode {
    Ok = 1,
    InvalidKey = 2,
    InvalidAlgorithm = 3,
    InvalidState = 4,
    InvalidInput = 5,
    InvalidNonce = 6,
    TagMismatch = 7,
    DataTooLarge = 8,
    AuthenticationFailed = 9,
    Unsupported = 10,
    BackendError = 11,
    EntropyUnavailable = 12,
    BufferTooSmall = 13,
    KeyNotFound = 14,
    KeyExpired = 15,
    UsageNotPermitted = 16,
    DeviceError = 17,
    Timeout = 18,
    ContextNotFound = 19,
    ConnectionError = 100,  // Client-side only
    ProtocolError = 101,    // Client-side only
};

/// Exception thrown by cryptod client operations.
class CryptoException : public std::runtime_error {
public:
    CryptoException(ErrorCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    /// Get the error code.
    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

/// Convenience function to throw a CryptoException.
[[noreturn]] inline void throw_error(ErrorCode code, const std::string& message) {
    throw CryptoException(code, message);
}

} // namespace cryptod
