// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <memory>
#include "icrypto_backend.h"
#include "crypto_config.h"
#include "keystore.h"

class CryptoDaemon
{
public:
    int run();
    void init(int argc, char *argv[]);

private:
    std::unique_ptr<ICryptoBackend> crypto_backend;
    KeyStore keystore;
    CryptoConfig config;
};
