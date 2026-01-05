// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "dummy_backend.h"
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include "dummy_hmac.h"
#include "crypto_exception.h"
#include "log_macro.h"

DummyHmac::DummyHmac(crypto_hash_alg_t algo, const SecureVector &key) : sum_(0)
{
    LOG_ENTRY("");
    sum_ = 0;
}

DummyHmac::~DummyHmac()
{
    LOG_ENTRY("");
}

void DummyHmac::init()
{
    LOG_ENTRY("");
}

void DummyHmac::update(const uint8_t *data, size_t len)
{
    LOG_ENTRY("len=%lu", len);
    sum_ += len;
}

bool DummyHmac::verify(const uint8_t *sig, size_t sig_len)
{
    throw CryptoException(CryptoException::Reason::Crypto, "Must not be called");
}

SecureVector DummyHmac::finish()
{
    SecureVector hmac(32);
    memset(hmac.data(), 0xAA, hmac.size());
    LOG_EXIT("sum=%lu", sum_);
    return hmac;
}

std::unique_ptr<ICryptoOperation> DummyBackend::createHMAC(crypto_hash_alg_t algo,
                                                            const SecureVector &key)
{
    LOG_ENTRY("alg=%u", algo);
    auto hmac = std::make_unique<DummyHmac>(algo, key);
    return hmac;
}
