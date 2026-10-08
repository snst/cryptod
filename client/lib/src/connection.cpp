// Connection handling implementation

#include "cryptod/client.hpp"
#include "cryptod/error.hpp"
#include "crypto_api.pb.h"

#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <vector>

namespace cryptod {
namespace internal {

/// Maximum message size (64KB)
constexpr size_t MAX_MESSAGE_SIZE = 65536;

/// Atomic counter for request IDs
static std::atomic<uint64_t> g_request_id{1};

/// Get next unique request ID
uint64_t next_request_id() {
    return g_request_id.fetch_add(1, std::memory_order_relaxed);
}

/// Send a protobuf message over the socket
void send_message(int fd, const ::crypto::CryptoRequest& request) {
    std::string data;
    if (!request.SerializeToString(&data)) {
        throw_error(ErrorCode::InvalidInput, "Failed to serialize request");
    }
    
    if (data.size() > MAX_MESSAGE_SIZE) {
        throw_error(ErrorCode::InvalidInput, "Message too large");
    }
    
    ssize_t sent = ::send(fd, data.data(), data.size(), 0);
    if (sent < 0) {
        throw_error(ErrorCode::ConnectionError, "Failed to send message");
    }
    if (static_cast<size_t>(sent) != data.size()) {
        throw_error(ErrorCode::ConnectionError, "Incomplete message send");
    }
}

/// Receive a protobuf response from the socket
::crypto::CryptoResponse recv_response(int fd) {
    std::vector<uint8_t> buffer(MAX_MESSAGE_SIZE);
    ssize_t received = ::recv(fd, buffer.data(), buffer.size(), 0);
    
    if (received < 0) {
        throw_error(ErrorCode::ConnectionError, "Failed to receive message");
    }
    if (received == 0) {
        throw_error(ErrorCode::ConnectionError, "Connection closed by server");
    }
    
    ::crypto::CryptoResponse response;
    if (!response.ParseFromArray(buffer.data(), static_cast<int>(received))) {
        throw_error(ErrorCode::InvalidInput, "Failed to parse response");
    }
    
    return response;
}

/// Send a request and wait for the response
::crypto::CryptoResponse request_response(int fd, ::crypto::CryptoRequest request) {
    // Set request ID
    uint64_t req_id = next_request_id();
    request.set_request_id(req_id);
    
    // Send request
    send_message(fd, request);
    
    // Receive response
    ::crypto::CryptoResponse response = recv_response(fd);
    
    // Verify request ID matches
    if (response.request_id() != req_id) {
        throw_error(ErrorCode::InvalidState, "Response ID mismatch");
    }
    
    // Check for error
    if (response.has_error() && response.error().code() != 0) {
        // Convert proto error code to our error code
        ErrorCode code = static_cast<ErrorCode>(response.error().code());
        throw_error(code, response.error().message());
    }
    
    return response;
}

/// Convert HashAlgorithm to proto enum
::crypto::HashAlgorithm to_proto(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::Unspecified: return ::crypto::HASH_ALGORITHM_UNSPECIFIED;
        case HashAlgorithm::Raw: return ::crypto::HASH_ALGORITHM_RAW;
        case HashAlgorithm::Sha1: return ::crypto::HASH_ALGORITHM_SHA1;
        case HashAlgorithm::Sha224: return ::crypto::HASH_ALGORITHM_SHA224;
        case HashAlgorithm::Sha256: return ::crypto::HASH_ALGORITHM_SHA256;
        case HashAlgorithm::Sha384: return ::crypto::HASH_ALGORITHM_SHA384;
        case HashAlgorithm::Sha512: return ::crypto::HASH_ALGORITHM_SHA512;
        case HashAlgorithm::Sha512_256: return ::crypto::HASH_ALGORITHM_SHA512_256;
        case HashAlgorithm::Sha3_224: return ::crypto::HASH_ALGORITHM_SHA3_224;
        case HashAlgorithm::Sha3_256: return ::crypto::HASH_ALGORITHM_SHA3_256;
        case HashAlgorithm::Sha3_384: return ::crypto::HASH_ALGORITHM_SHA3_384;
        case HashAlgorithm::Sha3_512: return ::crypto::HASH_ALGORITHM_SHA3_512;
    }
    throw_error(ErrorCode::InvalidInput, "Unknown hash algorithm");
}

/// Convert MacAlgorithm to proto enum
::crypto::MacAlgorithm to_proto(MacAlgorithm alg) {
    switch (alg) {
        case MacAlgorithm::Unspecified: return ::crypto::MAC_ALGORITHM_UNSPECIFIED;
        case MacAlgorithm::HmacSha1: return ::crypto::MAC_ALGORITHM_HMAC_SHA1;
        case MacAlgorithm::HmacSha224: return ::crypto::MAC_ALGORITHM_HMAC_SHA224;
        case MacAlgorithm::HmacSha256: return ::crypto::MAC_ALGORITHM_HMAC_SHA256;
        case MacAlgorithm::HmacSha384: return ::crypto::MAC_ALGORITHM_HMAC_SHA384;
        case MacAlgorithm::HmacSha512: return ::crypto::MAC_ALGORITHM_HMAC_SHA512;
        case MacAlgorithm::HmacSha3_256: return ::crypto::MAC_ALGORITHM_HMAC_SHA3_256;
        case MacAlgorithm::HmacSha3_384: return ::crypto::MAC_ALGORITHM_HMAC_SHA3_384;
        case MacAlgorithm::HmacSha3_512: return ::crypto::MAC_ALGORITHM_HMAC_SHA3_512;
        case MacAlgorithm::Cmac: return ::crypto::MAC_ALGORITHM_CMAC;
    }
    throw_error(ErrorCode::InvalidInput, "Unknown MAC algorithm");
}

/// Convert CipherMode to proto enum
::crypto::CipherMode to_proto(CipherMode mode) {
    switch (mode) {
        case CipherMode::Ecb: return ::crypto::CIPHER_MODE_ECB;
        case CipherMode::Cbc: return ::crypto::CIPHER_MODE_CBC;
        case CipherMode::Ctr: return ::crypto::CIPHER_MODE_CTR;
        case CipherMode::Cfb: return ::crypto::CIPHER_MODE_CFB;
        case CipherMode::Ofb: return ::crypto::CIPHER_MODE_OFB;
        case CipherMode::Gcm: return ::crypto::CIPHER_MODE_GCM;
        case CipherMode::Ccm: return ::crypto::CIPHER_MODE_CCM;
    }
    throw_error(ErrorCode::InvalidInput, "Unknown cipher mode");
}

/// Set KeyHandle in proto message
void set_key_handle(::crypto::KeyHandle* proto, const KeyHandle& handle) {
    proto->set_id(handle.id());
}

} // namespace internal
} // namespace cryptod
