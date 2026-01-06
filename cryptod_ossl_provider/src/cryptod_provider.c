// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "cryptod_provider.h"
#include "icrypto_client.h"

extern const OSSL_DISPATCH cdp_hmac_functions[];
// extern const OSSL_DISPATCH cdp_ecdsa_functions[];

/* Algorithm Query Table */
static const OSSL_ALGORITHM cdp_macs[] = {
    {"HMAC", "provider=libcryptod_provider", cdp_hmac_functions},
    {NULL, NULL, NULL}};

/* static const OSSL_ALGORITHM cdp_signatures[] = {
    {"ECDSA", "provider=libcryptod_provider", cdp_ecdsa_functions},
    {NULL, NULL, NULL}};
 */

static const OSSL_ALGORITHM *cdp_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    switch (operation_id)
    {
    case OSSL_OP_MAC:
        return cdp_macs;
    // case OSSL_OP_SIGNATURE:
    //     return cdp_signatures;
    default:
        return NULL;
    }
}

static void cdp_teardown(void *provctx)
{
    cc_disconnect(provctx);
}

/* Provider Dispatch Table */
static const OSSL_DISPATCH provider_functions[] = {
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))cdp_query},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))cdp_teardown},
    {0, NULL}};

/* Entry Point */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    void *ret = (void *)cc_connect();
    if (!ret)
        return 0;
    *provctx = ret;
    *out = provider_functions;
    return 1;
}
