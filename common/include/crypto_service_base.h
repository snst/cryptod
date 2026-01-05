// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "ikeystore.h"
#include "icrypto_backend.h"

class CryptoServiceBase
{
public:
    CryptoServiceBase(ICryptoBackend &crypto_backend, IKeyStore &keystore)
        : crypto_backend_(crypto_backend), keystore_(keystore)
    {
    }

protected:
    ICryptoBackend &crypto_backend_;
    IKeyStore &keystore_;
};
