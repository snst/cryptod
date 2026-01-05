// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "icrypto_backend.h"
#include <openssl/hmac.h>

class DummyHmac : public ICryptoOperation
{
private:
    size_t sum_;
public:
    DummyHmac(crypto_hash_alg_t algo, const SecureVector &key);
    ~DummyHmac();
    void init() override;
    void update(const uint8_t *data, size_t len) override;
    bool verify(const uint8_t *sig, size_t sig_len) override;
    SecureVector finish() override;
};
