// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <openssl/core.h>
#include "crypto_types.h"

typedef struct
{
    void *rpc;
    crypto_hash_alg_t hash_alg;
    crypto_key_id_t key_id;
} rpc_hmac_t;

bool parse_key(void *input, size_t len, uint32_t *key_out);
