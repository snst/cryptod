// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "dummy_backend.h"
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "crypto_exception.h"
#include "log_macro.h"

DummyEcdsa::DummyEcdsa(const std::string &curve, bool sign_mode,
                       const SecureVector &key_data)
    : sum_(0)
{
}

DummyEcdsa::~DummyEcdsa()
{
}

void DummyEcdsa::init()
{
}

void DummyEcdsa::update(const uint8_t *data, size_t len)
{
    sum_ += len;
}

SecureVector DummyEcdsa::finish()
{
    SecureVector ret;
    return ret;
}

bool DummyEcdsa::verify(const uint8_t *sig, size_t sig_len)
{

    return 1;
}

std::unique_ptr<ICryptoOperation> DummyBackend::createECDSA(const std::string &curve,
                                                            bool sign_mode,
                                                            const SecureVector &key_data)
{
    LOG_ENTRY("curve=%s, sign=%d", curve.c_str(), sign_mode);
    return std::make_unique<DummyEcdsa>(curve, sign_mode, key_data);
}
