// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdint.h>
#include "crypto_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    void *cc_connect();
    void cc_disconnect(void *rpc);
    int cc_hmac_init(void *rpc, crypto_key_id_t key_id, crypto_hash_alg_t hash_alg);
    int cc_hmac_update(void *rpc, const uint8_t *data, uint32_t len);
    int cc_hmac_final(void *rpc, uint8_t *data, uint32_t *len);

#ifdef __cplusplus
} // extern "C"
#endif
