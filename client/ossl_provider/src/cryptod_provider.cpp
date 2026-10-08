// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "cryptod_provider.h"
#include <errno.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

extern const OSSL_DISPATCH cdp_cryptod_store_functions[];
extern const OSSL_DISPATCH cdp_cryptod_keymgmt_functions[];
extern const OSSL_DISPATCH cdp_hmac_mac_functions[];
extern const OSSL_DISPATCH cdp_tls1_prf_functions[];

static const OSSL_ALGORITHM cdp_stores[] = {{CRYPTOD_STORE_SCHEME,
                                             "provider=libcryptod_provider",
                                             cdp_cryptod_store_functions},
                                            {NULL, NULL, NULL}};

static const OSSL_ALGORITHM cdp_keymgmts[] = {{CRYPTOD_SYM_KEY_TYPE,
                                               "provider=libcryptod_provider",
                                               cdp_cryptod_keymgmt_functions},
                                              {NULL, NULL, NULL}};

static const OSSL_ALGORITHM cdp_macs[] = {
    {"HMAC", "provider=libcryptod_provider", cdp_hmac_mac_functions},
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM cdp_kdfs[] = {
    {"TLS1-PRF", "provider=libcryptod_provider", cdp_tls1_prf_functions},
    {NULL, NULL, NULL}};

static const OSSL_PARAM *my_prov_gettable_params(void *provctx) {
  static const OSSL_PARAM gettable[] = {
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
      OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
      OSSL_PARAM_END};
  return gettable;
}

static int my_prov_get_params(void *provctx, OSSL_PARAM params[]) {
  OSSL_PARAM *p;

  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
  if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "libcryptod_provider"))
    return 0;

  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
  if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0"))
    return 0;

  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
  if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "dev"))
    return 0;

  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
  if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* 1 = active */
    return 0;

  return 1;
}

static const OSSL_ALGORITHM *cdp_query(void *provctx, int operation_id,
                                       int *no_cache) {
  *no_cache = 0;
  switch (operation_id) {
  case OSSL_OP_STORE:
    return cdp_stores;
  case OSSL_OP_KEYMGMT:
    return cdp_keymgmts;
  case OSSL_OP_MAC:
    return cdp_macs;
  case OSSL_OP_KDF:
    return cdp_kdfs;
  default:
    return NULL;
  }
}

static void cdp_teardown(void *provctx) {
  CryptodProviderContext *provider = PROV_CTX(provctx);
  provider->disconnect();
}

/* Provider Dispatch Table */
static const OSSL_DISPATCH provider_functions[] = {
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))cdp_query},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))cdp_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     (void (*)(void))my_prov_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))my_prov_get_params},
    {0, NULL}};

/* Entry Point */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx) {
  CryptodProviderContext *ctx = new CryptodProviderContext();
  void *ret = (void *)ctx;
  if (!ret)
    return 0;
  *provctx = ret;
  *out = provider_functions;
  return 1;
}
}

bool CryptodProviderKey::load() {
  if (provider_) {
    return provider_->load_key(this);
  }
  return false;
}

bool CryptodProviderContext::connect() {
  if (client_ == nullptr) {
    client_ = cryptod::Client::connect(CRYPTOD_SOCKET);
  }

  return client_ != nullptr;
}

void CryptodProviderContext::disconnect() { client_ = nullptr; }

bool CryptodProviderContext::load_key(CryptodProviderKey *key) {
  if (!key || key->key_label_.empty()) {
    return false;
  }
  return load_key(key->key_label_, key->key_handle_);
}

bool CryptodProviderContext::load_key(const std::string &key_label,
                                      cryptod::KeyHandle &key_handle) {
  if (key_label.empty()) {
    return false;
  }
  if (!connect())
    return false;

  auto query = cryptod::FindKeyQuery::by_label(key_label);
  auto result = client_->find_key(query);
  if (!result.has_value()) {
    key_handle.invalidate();
    return false;
  }

  key_handle = result.value();
  return true;
}

std::unique_ptr<cryptod::MacContext>
CryptodProviderContext::mac_init(cryptod::MacAlgorithm algorithm,
                                 const cryptod::KeyHandle &key) {
  return client_->mac(algorithm, key);
}