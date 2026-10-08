// Hash context implementation

#include "cryptod/hash.hpp"
#include "cryptod/error.hpp"
#include "crypto_api.pb.h"

namespace cryptod {

// Internal declarations from connection.cpp
namespace internal {
    ::crypto::CryptoResponse request_response(int fd, ::crypto::CryptoRequest request);
}

HashContextImpl::HashContextImpl(int fd, uint64_t handle, uint32_t output_size)
    : fd_(fd), handle_(handle), output_size_(output_size), finished_(false) {}

HashContextImpl::~HashContextImpl() {
    if (!finished_ && handle_ != 0) {
        // Clean up the context on the server side
        try {
            ::crypto::CryptoRequest req;
            auto* destroy = req.mutable_destroy_context();
            destroy->set_context_handle(handle_);
            internal::request_response(fd_, std::move(req));
        } catch (...) {
            // Ignore errors in destructor
        }
    }
}

void HashContextImpl::update(std::span<const uint8_t> data) {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "Hash context already finished");
    }
    
    ::crypto::CryptoRequest req;
    auto* update = req.mutable_hash_update();
    update->set_context_handle(handle_);
    update->set_data(data.data(), data.size());
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_hash_update()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
}

std::vector<uint8_t> HashContextImpl::finish() {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "Hash context already finished");
    }
    finished_ = true;
    
    ::crypto::CryptoRequest req;
    auto* finish = req.mutable_hash_finish();
    finish->set_context_handle(handle_);
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_hash_finish()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& digest = resp.hash_finish().digest();
    return {digest.begin(), digest.end()};
}

size_t HashContextImpl::output_size() const {
    return output_size_;
}

} // namespace cryptod
