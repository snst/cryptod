// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdint.h>

typedef uint32_t crypto_key_id_t;

typedef enum
{
    HASH_ALG_INVALID = 0,
    HASH_ALG_NONE = 1,
    HASH_ALG_SHA1 = 2,
    HASH_ALG_SHA224 = 3,
    HASH_ALG_SHA256 = 4,
    HASH_ALG_SHA384 = 5,
    HASH_ALG_SHA512 = 6,
} crypto_hash_alg_t;
