// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdint.h>
#include "crypto_types.h"
#include "crypto_codes.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        void *rpc_;
        uint32_t session_id_;
        crypto_hash_alg_t hash_alg_;
        crypto_key_id_t key_id_;
    } rpc_hmac_t;

    void *cc_connect();
    void cc_disconnect(void *context);
    crypto_code_t cc_hmac_init(rpc_hmac_t *hmac_ctx);
    crypto_code_t cc_hmac_update(rpc_hmac_t *hmac_ctx, const uint8_t *data, uint32_t len);
    crypto_code_t cc_hmac_final(rpc_hmac_t *hmac_ctx, uint8_t *out, uint32_t *out_len);

#ifdef __cplusplus
} // extern "C"
#endif
