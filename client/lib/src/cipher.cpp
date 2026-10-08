// Cipher context implementation

#include "cryptod/cipher.hpp"
#include "cryptod/error.hpp"
#include "crypto_api.pb.h"

namespace cryptod {

// Internal declarations from connection.cpp
namespace internal {
    ::crypto::CryptoResponse request_response(int fd, ::crypto::CryptoRequest request);
}

CipherContextImpl::CipherContextImpl(int fd, uint64_t handle, bool encrypting, bool is_aead)
    : fd_(fd), handle_(handle), encrypting_(encrypting), is_aead_(is_aead), finished_(false) {}

CipherContextImpl::~CipherContextImpl() {
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

std::vector<uint8_t> CipherContextImpl::update(std::span<const uint8_t> input) {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "Cipher context already finished");
    }
    
    ::crypto::CryptoRequest req;
    auto* update = req.mutable_cipher_update();
    update->set_context_handle(handle_);
    update->set_input(input.data(), input.size());
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_cipher_update()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& output = resp.cipher_update().output();
    return {output.begin(), output.end()};
}

void CipherContextImpl::set_tag(std::span<const uint8_t> tag) {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "Cipher context already finished");
    }
    if (!is_aead_ || encrypting_) {
        throw_error(ErrorCode::InvalidState, "set_tag only valid for AEAD decryption");
    }
    
    ::crypto::CryptoRequest req;
    auto* set_tag = req.mutable_cipher_set_tag();
    set_tag->set_context_handle(handle_);
    set_tag->set_tag(tag.data(), tag.size());
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_cipher_set_tag()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
}

std::vector<uint8_t> CipherContextImpl::finish() {
    if (finished_) {
        throw_error(ErrorCode::InvalidState, "Cipher context already finished");
    }
    finished_ = true;
    
    ::crypto::CryptoRequest req;
    auto* finish = req.mutable_cipher_finish();
    finish->set_context_handle(handle_);
    
    auto resp = internal::request_response(fd_, std::move(req));
    if (!resp.has_cipher_finish()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& output = resp.cipher_finish().output();
    
    // Store the tag if AEAD encryption
    if (is_aead_ && encrypting_ && !resp.cipher_finish().tag().empty()) {
        const auto& tag_data = resp.cipher_finish().tag();
        tag_ = std::vector<uint8_t>(tag_data.begin(), tag_data.end());
    }
    
    return {output.begin(), output.end()};
}

std::optional<std::vector<uint8_t>> CipherContextImpl::get_tag() const {
    return tag_;
}

bool CipherContextImpl::is_aead() const {
    return is_aead_;
}

} // namespace cryptod
