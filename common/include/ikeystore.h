// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "crypto_result.h"

class IKeyStore
{
public:
    virtual Result getKey(uint32_t keyId) = 0;
};
