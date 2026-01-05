// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "icrypto_backend.h"
#include "crypto_types.h"
#include "dummy_ecdsa.h"
#include "dummy_hmac.h"

class DummyBackend : public ICryptoBackend
{
public:
    std::unique_ptr<ICryptoOperation> createHMAC(crypto_hash_alg_t algo,
                                                const SecureVector &key) override;
    std::unique_ptr<ICryptoOperation> createECDSA(const std::string &curve,
                                                 bool sign_mode,
                                                 const SecureVector &key_data) override;
};
