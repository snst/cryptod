// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "ossl_backend.h"
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include "ossl_hmac.h"
#include "crypto_exception.h"

#define ENABLE_LOGGING
#include "log_macro.h"

OsslHmac::OsslHmac(crypto_hash_alg_t algo, const SecureVector &key) : ctx_(HMAC_CTX_new()), initialized_(false)
{
    LOG_ENTRY("");
    if (!ctx_)
        throw CryptoException(CryptoException::Reason::Crypto, "HMAC_CTX_new failed");

    const EVP_MD *md = nullptr;
    switch (algo)
    {
    case HASH_ALG_SHA1:
        md = EVP_sha1();
        break;
    case HASH_ALG_SHA224:
        md = EVP_sha224();
        break;
    case HASH_ALG_SHA256:
        md = EVP_sha256();
        break;
    case HASH_ALG_SHA384:
        md = EVP_sha384();
        break;
    case HASH_ALG_SHA512:
        md = EVP_sha512();
        break;
    default:
        throw CryptoException(CryptoException::Reason::Crypto, "Unsupported HMAC algo: " + algo);
    }

    HMAC_Init_ex(ctx_, key.data(), key.size(), md, nullptr);
}

OsslHmac::~OsslHmac()
{
    LOG_ENTRY("");
    if (ctx_)
        HMAC_CTX_free(ctx_);
}

void OsslHmac::init()
{
    LOG_ENTRY("");
    initialized_ = true;
    HMAC_Init_ex(ctx_, nullptr, 0, nullptr, nullptr); // Reset
}

void OsslHmac::update(const uint8_t *data, size_t len)
{
    LOG_ENTRY("len=%lu", len);
    if (!initialized_)
        throw CryptoException(CryptoException::Reason::Crypto, "Must call init() first");
    HMAC_Update(ctx_, data, len);
}

bool OsslHmac::verify(const uint8_t *sig, size_t sig_len)
{
    throw CryptoException(CryptoException::Reason::Crypto, "Must not be called");
}

SecureVector OsslHmac::finish()
{
    uint32_t len = 0;
    SecureVector hmac(128);
    HMAC_Final(ctx_, hmac.data(), &len);
    hmac.resize(len);
    LOG_EXIT("len=%u", len);
    return hmac;
}

std::unique_ptr<ICryptoOperation> OpenSSLBackend::createHMAC(crypto_hash_alg_t algo,
                                                            const SecureVector &key)
{
    LOG_ENTRY("alg=%u", algo);
    auto hmac = std::make_unique<OsslHmac>(algo, key);
    return hmac;
}
