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
    void cc_disconnect(void *context);
    int cc_hmac_init(void *context, crypto_key_id_t key_id, crypto_hash_alg_t hash_alg);
    int cc_hmac_update(void *context, const uint8_t *data, uint32_t len);
    int cc_hmac_final(void *context, uint8_t *out, uint32_t *out_len);

#ifdef __cplusplus
} // extern "C"
#endif
