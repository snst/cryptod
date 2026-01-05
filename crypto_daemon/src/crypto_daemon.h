// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <memory>
#include "crypto_config.h"
#include "keystore.h"
#ifdef USE_CRYPTO_BACKEND_OPENSSL
#include "ossl_backend.h"
#endif
#ifdef USE_CRYPTO_BACKEND_DUMMY
#include "dummy_backend.h"
#endif

class CryptoDaemon
{
public:
    int run();
    void init(int argc, char *argv[]);

private:
    KeyStore keystore;
    CryptoConfig config;
#ifdef USE_CRYPTO_BACKEND_OPENSSL
    OpenSSLBackend crypto_backend;
#endif
#ifdef USE_CRYPTO_BACKEND_DUMMY
    DummyBackend crypto_backend;
#endif
};
