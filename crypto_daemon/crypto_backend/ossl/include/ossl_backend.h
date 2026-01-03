// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "crypto_backend.h"
#include "crypto_types.h"
#include "ossl_ecdsa.h"
#include "ossl_hmac.h"

class OpenSSLBackend : public ICryptoBackend
{
public:
    std::unique_ptr<ICryptoOperation> createHMAC(crypto_hash_alg_t algo,
                                                const SecureVector &key) override;
    std::unique_ptr<ICryptoOperation> createECDSA(const std::string &curve,
                                                 bool sign_mode,
                                                 const SecureVector &key_data) override;
};
