// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "ikeystore.h"
#include "icrypto_backend.h"

class ICryptoService
{
public:
    virtual int32_t run(ICryptoBackend* crypto_backend, IKeyStore* keystore, const char* path) = 0;
};
