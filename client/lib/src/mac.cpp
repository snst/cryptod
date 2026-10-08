// MAC context implementation

#include "cryptod/mac.hpp"
#include "cryptod/error.hpp"
#include "crypto_api.pb.h"

namespace cryptod {

// Internal declarations from connection.cpp
namespace internal {
    ::crypto::CryptoResponse request_response(int fd, ::crypto::CryptoRequest request);
}

MacContextImpl::MacContextImpl(int fd, uint64_t handle, uint32_t output_size)
    : fd_(fd), handle_(handle), output_size_(output_size), finished_(false) {}

MacContextImpl::~MacContextImpl() {
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

void MacContextImpl::update(std::span<const uint8_t> data) {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "MAC context already finished");
    }
    
    ::crypto::CryptoRequest req;
    auto* update = req.mutable_mac_update();
    update->set_context_handle(handle_);
    update->set_data(data.data(), data.size());
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_mac_update()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
}

void MacContextImpl::update(const uint8_t* data, size_t len) {
    update(std::span<const uint8_t>(data, len));
}

std::vector<uint8_t> MacContextImpl::finish() {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "MAC context already finished");
    }
    finished_ = true;
    
    ::crypto::CryptoRequest req;
    auto* finish = req.mutable_mac_finish();
    finish->set_context_handle(handle_);
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_mac_finish()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& tag = resp.mac_finish().tag();
    return {tag.begin(), tag.end()};
}

bool MacContextImpl::verify(std::span<const uint8_t> expected_tag) {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "MAC context already finished");
    }
    finished_ = true;
    
    ::crypto::CryptoRequest req;
    auto* verify = req.mutable_mac_verify();
    verify->set_context_handle(handle_);
    verify->set_expected_tag(expected_tag.data(), expected_tag.size());
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_mac_verify()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    return resp.mac_verify().valid();
}

size_t MacContextImpl::output_size() const {
    return output_size_;
}

} // namespace cryptod
