// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "icrypto_backend.h"
#include <openssl/ecdsa.h>

class OsslEcdsa : public ICryptoOperation
{
private:
    EVP_PKEY *pkey_;
    EVP_MD_CTX *mdctx_;
    bool sign_mode_;
    bool initialized_;

public:
    OsslEcdsa(const std::string &curve, bool sign_mode, const SecureVector &key_data);
    ~OsslEcdsa();
    void init() override;
    void update(const uint8_t *data, size_t len) override;
    bool verify(const uint8_t *sig, size_t sig_len);
    SecureVector finish() override;
};
