// cryptod client implementation

#include "cryptod/client.hpp"
#include "cryptod/error.hpp"
#include "cryptod/hash.hpp"
#include "cryptod/mac.hpp"
#include "cryptod/cipher.hpp"
#include "cryptod/kdf.hpp"
#include "crypto_api.pb.h"

#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace cryptod {

// Internal declarations from connection.cpp
namespace internal {
    ::crypto::CryptoResponse request_response(int fd, ::crypto::CryptoRequest request);
    ::crypto::HashAlgorithm to_proto(HashAlgorithm alg);
    ::crypto::MacAlgorithm to_proto(MacAlgorithm alg);
    ::crypto::CipherMode to_proto(CipherMode mode);
    void set_key_handle(::crypto::KeyHandle* proto, const KeyHandle& handle);
}

class Client::Impl {
public:
    explicit Impl(int fd) : fd_(fd) {}
    
    ~Impl() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    int fd() const { return fd_; }

private:
    int fd_;
};

Client::Client() = default;
Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

int Client::fd() const {
    return impl_ ? impl_->fd() : -1;
}

std::unique_ptr<Client> Client::connect(const std::string& socket_path) {
    // Create SOCK_SEQPACKET socket
    int fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        throw_error(ErrorCode::ConnectionError, "Failed to create socket");
    }

    // Set up address
    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        throw_error(ErrorCode::InvalidInput, "Socket path too long");
    }
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    // Connect
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        throw_error(ErrorCode::ConnectionError, "Failed to connect to daemon");
    }

    auto client = std::unique_ptr<Client>(new Client());
    client->impl_ = std::make_unique<Impl>(fd);
    return client;
}

KeyHandle Client::create_key(const CreateKeyParams& params) {
    ::crypto::CryptoRequest req;
    auto* create = req.mutable_create_key();
    
    create->set_label(params.label);
    create->set_extractable(params.extractable);
    create->set_size_bits(static_cast<uint32_t>(params.key_size));
    
    // Set algorithm to symmetric
    auto* alg = create->mutable_algorithm();
    alg->set_symmetric(true);
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_create_key()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& handle = resp.create_key().handle();
    return KeyHandle(handle.id());
}

KeyHandle Client::import_key(const ImportKeyParams& params) {
    ::crypto::CryptoRequest req;
    auto* import = req.mutable_import_key();
    
    import->set_label(params.label);
    import->set_material(params.material.data(), params.material.size());
    import->set_extractable(params.extractable);
    import->set_format(static_cast<::crypto::KeyFormat>(static_cast<int>(params.format)));
    
    // Set algorithm based on key size
    auto* alg = import->mutable_algorithm();
    alg->set_symmetric(true);
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_import_key()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& handle = resp.import_key().handle();
    return KeyHandle(handle.id());
}

KeyInfo Client::get_key_info(const KeyHandle& key) {
    ::crypto::CryptoRequest req;
    auto* get = req.mutable_get_key_info();
    internal::set_key_handle(get->mutable_handle(), key);
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_get_key_info()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& info = resp.get_key_info().info();
    KeyInfo result;
    result.extractable = info.extractable();
    if (info.has_size_bits()) {
        result.size_bits = info.size_bits();
    }
    if (!info.label().empty()) {
        result.label = info.label();
    }
    return result;
}

void Client::delete_key(const KeyHandle& key) {
    ::crypto::CryptoRequest req;
    auto* del = req.mutable_delete_key();
    internal::set_key_handle(del->mutable_handle(), key);
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_delete_key()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
}

std::vector<uint8_t> Client::export_key(const KeyHandle& key, KeyFormat format) {
    ::crypto::CryptoRequest req;
    auto* exp = req.mutable_export_key();
    internal::set_key_handle(exp->mutable_handle(), key);
    exp->set_format(static_cast<::crypto::KeyFormat>(static_cast<int>(format)));
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_export_key()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& material = resp.export_key().material();
    return {material.begin(), material.end()};
}

std::optional<KeyHandle> Client::find_key(const FindKeyQuery& query) {
    ::crypto::CryptoRequest req;
    auto* find = req.mutable_find_key();
    auto* q = find->mutable_query();
    
    q->set_label(query.label);
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_find_key()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    if (!resp.find_key().has_handle()) {
        return std::nullopt;
    }
    
    const auto& handle = resp.find_key().handle();
    return KeyHandle(handle.id());
}

std::unique_ptr<HashContext> Client::hash(HashAlgorithm algorithm) {
    ::crypto::CryptoRequest req;
    auto* hash_create = req.mutable_hash_create();
    hash_create->set_algorithm(internal::to_proto(algorithm));
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_hash_create()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    return std::make_unique<HashContextImpl>(
        impl_->fd(),
        resp.hash_create().context_handle(),
        resp.hash_create().output_size()
    );
}

std::unique_ptr<MacContext> Client::mac(MacAlgorithm algorithm, const KeyHandle& key) {
    ::crypto::CryptoRequest req;
    auto* mac_create = req.mutable_mac_create();
    mac_create->set_algorithm(internal::to_proto(algorithm));
    internal::set_key_handle(mac_create->mutable_key(), key);
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_mac_create()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    return std::make_unique<MacContextImpl>(
        impl_->fd(),
        resp.mac_create().context_handle(),
        resp.mac_create().output_size()
    );
}

std::unique_ptr<CipherContext> Client::cipher_encrypt(const CipherParams& params, const KeyHandle& key) {
    ::crypto::CryptoRequest req;
    auto* create = req.mutable_cipher_create();
    create->set_encrypt(true);
    internal::set_key_handle(create->mutable_key(), key);
    
    auto* proto_params = create->mutable_params();
    proto_params->set_mode(internal::to_proto(params.mode));
    if (!params.iv.empty()) {
        proto_params->set_iv(params.iv.data(), params.iv.size());
    }
    if (!params.aad.empty()) {
        proto_params->set_aad(params.aad.data(), params.aad.size());
    }
    if (params.tag_len) {
        proto_params->set_tag_len(*params.tag_len);
    }
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_cipher_create()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    return std::make_unique<CipherContextImpl>(
        impl_->fd(),
        resp.cipher_create().context_handle(),
        true, // encrypting
        resp.cipher_create().is_aead()
    );
}

std::unique_ptr<CipherContext> Client::cipher_decrypt(const CipherParams& params, const KeyHandle& key) {
    ::crypto::CryptoRequest req;
    auto* create = req.mutable_cipher_create();
    create->set_encrypt(false);
    internal::set_key_handle(create->mutable_key(), key);
    
    auto* proto_params = create->mutable_params();
    proto_params->set_mode(internal::to_proto(params.mode));
    if (!params.iv.empty()) {
        proto_params->set_iv(params.iv.data(), params.iv.size());
    }
    if (!params.aad.empty()) {
        proto_params->set_aad(params.aad.data(), params.aad.size());
    }
    if (params.tag_len) {
        proto_params->set_tag_len(*params.tag_len);
    }
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_cipher_create()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    return std::make_unique<CipherContextImpl>(
        impl_->fd(),
        resp.cipher_create().context_handle(),
        false, // decrypting
        resp.cipher_create().is_aead()
    );
}

std::vector<uint8_t> Client::generate_random(size_t length) {
    ::crypto::CryptoRequest req;
    auto* gen = req.mutable_generate_random();
    gen->set_length(static_cast<uint32_t>(length));
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_generate_random()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& data = resp.generate_random().data();
    return {data.begin(), data.end()};
}

std::vector<uint8_t> Client::derive_key(const KdfParams& params) {
    ::crypto::CryptoRequest req;
    auto* derive = req.mutable_derive_key();
    
    // Set algorithm
    switch (params.algorithm) {
        case KdfAlgorithm::HkdfSha256:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_HKDF_SHA256);
            break;
        case KdfAlgorithm::HkdfSha384:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_HKDF_SHA384);
            break;
        case KdfAlgorithm::HkdfSha512:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_HKDF_SHA512);
            break;
        case KdfAlgorithm::Pbkdf2Sha256:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_PBKDF2_SHA256);
            break;
        case KdfAlgorithm::Pbkdf2Sha384:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_PBKDF2_SHA384);
            break;
        case KdfAlgorithm::Pbkdf2Sha512:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_PBKDF2_SHA512);
            break;
        case KdfAlgorithm::Tls12EmsPrfSha256:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_TLS12_EMS_PRF_SHA256);
            break;
        case KdfAlgorithm::Tls12EmsPrfSha384:
            derive->set_algorithm(::crypto::KDF_ALGORITHM_TLS12_EMS_PRF_SHA384);
            break;
    }
    
    // Set IKM
    //derive->set_ikm(params.ikm.data(), params.ikm.size());

    //derive->set

   
    // Set output length
    derive->set_output_len(static_cast<uint32_t>(params.output_len));

    internal::set_key_handle(derive->mutable_key(), params.key_handle);
    
    // Set optional parameters
    if (params.salt && !params.salt->empty()) {
        derive->set_salt(params.salt->data(), params.salt->size());
    }
    
    if (params.info && !params.info->empty()) {
        derive->set_info(params.info->data(), params.info->size());
    }
    
    if (params.iterations) {
        derive->set_iterations(*params.iterations);
    }
    
    auto resp = internal::request_response(impl_->fd(), std::move(req));
    if (!resp.has_derive_key()) {
        throw_error(ErrorCode::InvalidState, "Invalid response type");
    }
    
    const auto& derived = resp.derive_key().derived_key();
    return {derived.begin(), derived.end()};
}

} // namespace cryptod
