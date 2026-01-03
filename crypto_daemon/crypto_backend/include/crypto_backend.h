// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <stdexcept>
#include "crypto_types.h"
#include "secure_vector.h"

class ICryptoOperation
{
public:
    virtual ~ICryptoOperation() = default;
    virtual void init() = 0;
    virtual void update(const uint8_t *data, size_t len) = 0;
    virtual SecureVector finish() = 0;
    virtual bool verify(const uint8_t *sig, size_t sig_len) = 0;
};

class ICryptoBackend
{
public:
    virtual ~ICryptoBackend() = default;
    virtual std::unique_ptr<ICryptoOperation> createHMAC(crypto_hash_alg_t algo,
                                                         const SecureVector &key) = 0;
    virtual std::unique_ptr<ICryptoOperation> createECDSA(const std::string &curve,
                                                          bool sign_mode,
                                                          const SecureVector &key_data) = 0;
};
