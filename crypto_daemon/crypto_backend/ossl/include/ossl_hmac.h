// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "crypto_backend.h"
#include <openssl/hmac.h>

class OsslHmac : public ICryptoOperation
{
private:
    HMAC_CTX *ctx_;
    bool initialized_;

public:
    OsslHmac(crypto_hash_alg_t algo, const SecureVector &key);
    ~OsslHmac();
    void init() override;
    void update(const uint8_t *data, size_t len) override;
    bool verify(const uint8_t *sig, size_t sig_len) override;
    SecureVector finish() override;
};
