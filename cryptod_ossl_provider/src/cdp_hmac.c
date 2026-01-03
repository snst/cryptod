// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "crypto_client.h"
#include "crypto_utils.h"
#include "cryptod_provider.h"

#define ENABLE_LOGGING
#include "log_macro.h"

/* Function Prototypes */
static OSSL_FUNC_mac_newctx_fn cdp_hmac_newctx;
static OSSL_FUNC_mac_freectx_fn cdp_hmac_freectx;
static OSSL_FUNC_mac_init_fn cdp_hmac_init;
static OSSL_FUNC_mac_update_fn cdp_hmac_update;
static OSSL_FUNC_mac_final_fn cdp_hmac_final;

static int cdp_hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static void *cdp_hmac_newctx(void *vrpc_ctx)
{
    rpc_hmac_t *hmac_ctx = malloc(sizeof(rpc_hmac_t));
    LOG_ENTRY("hmac_ctx=%p", hmac_ctx);
    if (hmac_ctx != NULL)
    {
        hmac_ctx->rpc = vrpc_ctx;
    }
    return hmac_ctx;
}

static rpc_hmac_t *cdp_hmac_dup(rpc_hmac_t *src)
{
    LOG_ENTRY("src=%p", src);
    rpc_hmac_t *dst = NULL;
    return dst;
}

static void cdp_hmac_freectx(void *vhmac_ctx)
{
    LOG_ENTRY("vhmac_ctx=%p", vhmac_ctx);
    if (NULL != vhmac_ctx)
    {
        rpc_hmac_t *hmac_ctx = (rpc_hmac_t *)vhmac_ctx;
        free(hmac_ctx);
    }
}

static int cdp_hmac_init(void *vhmac_ctx, const unsigned char *key,
                         size_t keylen, const OSSL_PARAM params[])
{
    LOG_ENTRY("vhmac_ctx=%p", vhmac_ctx);
    rpc_hmac_t *hmac_ctx = (rpc_hmac_t *)vhmac_ctx;

    // Even if params is empty, return 1.
    // The digest might have been set previously via set_ctx_params.
    if (params != NULL)
    {
        return cdp_hmac_set_ctx_params(vhmac_ctx, params);
    }

    int ret = cc_hmac_init(hmac_ctx->rpc, hmac_ctx->key_id, hmac_ctx->hash_alg);

    return ret;
}

static int cdp_hmac_update(void *vhmac_ctx, const unsigned char *data, size_t datalen)
{
    LOG_ENTRY("hmac_ctx=%p, len=%lu bytes", vhmac_ctx, datalen);
    rpc_hmac_t *hmac_ctx = (rpc_hmac_t *)vhmac_ctx;
    int ret = cc_hmac_update(hmac_ctx->rpc, data, datalen);
    return ret;
}

static int cdp_hmac_final(void *vhmac_ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    LOG_ENTRY("vhmac_ctx=%p, outsz=%lu", vhmac_ctx, outsz);
    rpc_hmac_t *hmac_ctx = (rpc_hmac_t *)vhmac_ctx;

    if (outsz < 32)
        return 0;
    uint32_t out_len = (uint32_t)outsz;
    int ret = cc_hmac_final(hmac_ctx->rpc, out, &out_len);
    *outl = out_len;
    return ret;
}

static int cdp_hmac_get_ctx_params(void *vhmac_ctx, OSSL_PARAM params[])
{
    LOG_ENTRY("vhmac_ctx=%p", vhmac_ctx);
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
    {
        LOG_INFO("-OSSL_MAC_PARAM_SIZE: 32");
        return OSSL_PARAM_set_size_t(p, 32);
    }
    return 1;
}

static const OSSL_PARAM *cdp_hmac_gettable_ctx_params(void *vhmac_ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END};
    return known_gettable_ctx_params;
}

static const OSSL_PARAM *cdp_hmac_settable_ctx_params(void *vhmac_ctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_END};
    return known_settable_ctx_params;
}

static int cdp_hmac_set_ctx_params(void *vhmac_ctx, const OSSL_PARAM params[])
{
    LOG_ENTRY("");
    rpc_hmac_t *hmac_ctx = (rpc_hmac_t *)vhmac_ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    /* Handle "digest" (e.g., -digest SHA1) */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        hmac_ctx->hash_alg = hash_alg_from_string((char *)p->data, p->data_size);
        LOG_INFO(" OSSL_MAC_PARAM_DIGEST: %s (%d)", (char *)p->data, hmac_ctx->hash_alg);
    }

    /* Handle "properties" (if -propquery is passed) */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_PROPERTIES);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        LOG_INFO(" OSSL_MAC_PARAM_PROPERTIES: %s", (char *)p->data);
    }

    /* Handle "key" (if passed via params instead of the init function) */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (p->data_size > 0 && p->data_size <= sizeof(hmac_ctx->key_id))
        {
            uint8_t *buf = (uint8_t *)p->data;
            hmac_ctx->key_id = buf[0];
            for (size_t i = 1; i < p->data_size; i++)
            {
                hmac_ctx->key_id <<= 8;
                hmac_ctx->key_id |= buf[i];
            }
        }
        LOG_INFO(" OSSL_MAC_PARAM_KEY: length: %zu", p->data_size);
    }

    /* * IMPORTANT: Return 1 even if no recognized parameters were found,
     * so long as the parameters that WERE found were handled correctly.
     */
    return 1;
}

/* Dispatch Table for HMAC Algorithm */
const OSSL_DISPATCH cdp_hmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))cdp_hmac_newctx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))cdp_hmac_dup},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))cdp_hmac_freectx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))cdp_hmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))cdp_hmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))cdp_hmac_final},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))cdp_hmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))cdp_hmac_get_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))cdp_hmac_settable_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))cdp_hmac_set_ctx_params},
    {0, NULL}};
