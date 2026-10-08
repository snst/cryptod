// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "cryptod_provider.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

extern "C" {


static OSSL_FUNC_store_open_fn cdp_cryptod_store_open;
static OSSL_FUNC_store_set_ctx_params_fn cdp_cryptod_store_set_ctx_params;
static OSSL_FUNC_store_load_fn cdp_cryptod_store_load;
static OSSL_FUNC_store_eof_fn cdp_cryptod_store_eof;
static OSSL_FUNC_store_close_fn cdp_cryptod_store_close;

static void *cdp_cryptod_store_open(void *provctx, const char *uri) {
  (void)provctx;
  CryptodProviderContext *provider = PROV_CTX(provctx);

  if (uri == NULL) {
    return NULL;
  }

  std::string_view uri_view(uri);
  constexpr std::string_view prefix = "cryptod:";

  if (!uri_view.starts_with(prefix)) {
    return NULL;
  }

  std::string key_label(uri_view.substr(prefix.size()));
  auto *ctx = new CryptodStoreContext(provider, key_label);
  return ctx;
}

static int cdp_cryptod_store_set_ctx_params(void *loaderctx,
                                            const OSSL_PARAM params[]) {
  (void)loaderctx;
  (void)params;
  return OSSL_OK;
}

static int cdp_cryptod_store_load(void *loaderctx, OSSL_CALLBACK *object_cb,
                                  void *object_cbarg,
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                  void *pw_cbarg) {
  (void)pw_cb;
  (void)pw_cbarg;

  CryptodStoreContext *store_ctx = static_cast<CryptodStoreContext *>(loaderctx);
  if (store_ctx == NULL || object_cb == NULL) {
    return OSSL_ERR;
  }

  CryptodProviderKey *key_ref = new CryptodProviderKey(store_ctx->provider_, store_ctx->key_label_);

  int object_type = OSSL_OBJECT_PKEY;
  OSSL_PARAM params[4];
  params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
  params[1] = OSSL_PARAM_construct_utf8_string(
      OSSL_OBJECT_PARAM_DATA_TYPE, const_cast<char *>(CRYPTOD_SYM_KEY_TYPE),
      0);
  params[2] = OSSL_PARAM_construct_octet_string(
      OSSL_OBJECT_PARAM_REFERENCE, static_cast<void *>(&key_ref),
      sizeof(key_ref));
  params[3] = OSSL_PARAM_construct_end();

  int cb_result = object_cb(params, object_cbarg);
  if (cb_result == OSSL_OK) {
    return OSSL_OK;
  }

  delete key_ref;
  return OSSL_ERR;
}

static int cdp_cryptod_store_eof(void *loaderctx) {
  CryptodStoreContext *ctx = static_cast<CryptodStoreContext *>(loaderctx);
  return ctx != NULL ? 0 : 1;
}

static int cdp_cryptod_store_close(void *loaderctx) {
  delete static_cast<CryptodStoreContext *>(loaderctx);
  return OSSL_OK;
}

extern const OSSL_DISPATCH cdp_cryptod_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))cdp_cryptod_store_open},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS,
     (void (*)(void))cdp_cryptod_store_set_ctx_params},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))cdp_cryptod_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))cdp_cryptod_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))cdp_cryptod_store_close},
    {0, NULL}};

} // extern "C"