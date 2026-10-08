// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "cryptod_provider.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

extern "C" {

static OSSL_FUNC_keymgmt_new_fn cdp_cryptod_keyid_new;
static OSSL_FUNC_keymgmt_free_fn cdp_cryptod_keyid_free;
static OSSL_FUNC_keymgmt_load_fn cdp_cryptod_keyid_load;
static OSSL_FUNC_keymgmt_get_params_fn cdp_cryptod_keyid_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn cdp_cryptod_keyid_gettable_params;
static OSSL_FUNC_keymgmt_has_fn cdp_cryptod_keyid_has;
static OSSL_FUNC_keymgmt_match_fn cdp_cryptod_keyid_match;
static OSSL_FUNC_keymgmt_dup_fn cdp_cryptod_keyid_dup;
static OSSL_FUNC_keymgmt_query_operation_name_fn
    cdp_cryptod_keyid_query_operation_name;

static void *cdp_cryptod_keyid_new(void *provctx) {
  return new CryptodProviderKey(PROV_CTX(provctx));
}

static void cdp_cryptod_keyid_free(void *keydata) {
  delete static_cast<CryptodProviderKey *>(keydata);
}

static void *cdp_cryptod_keyid_load(const void *reference, size_t reference_sz) {
  if (reference == NULL || reference_sz != sizeof(CryptodProviderKey *)) {
    return NULL;
  }

  CryptodProviderKey *key =
      *static_cast<CryptodProviderKey *const *>(reference);

  if (!key || !key->load()) {
    return NULL;
  }

  return key;
}

static int cdp_cryptod_keyid_get_params(void *keydata, OSSL_PARAM params[]) {
  OSSL_PARAM *param = NULL;

  if ((param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
      !OSSL_PARAM_set_size_t(param, 64)) {
    return OSSL_ERR;
  }

  if ((param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
      !OSSL_PARAM_set_int(param, 512)) {
    return OSSL_ERR;
  }

  if ((param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) !=
          NULL &&
      !OSSL_PARAM_set_int(param, 256)) {
    return OSSL_ERR;
  }

  return OSSL_OK;
}

static const OSSL_PARAM *cdp_cryptod_keyid_gettable_params(void *provctx) {
  static const OSSL_PARAM params[] = {
      OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
      OSSL_PARAM_END};
  return params;
}

static int cdp_cryptod_keyid_has(const void *keydata, int selection) {
  const CryptodProviderKey *key = static_cast<const CryptodProviderKey *>(keydata);

  if (key == NULL) {
    return OSSL_ERR;
  }

  if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
    return !key->key_label_.empty();
  }

  return OSSL_OK;
}

static int cdp_cryptod_keyid_match(const void *keydata1, const void *keydata2,
                                  int selection) {
  const CryptodProviderKey *key1 = static_cast<const CryptodProviderKey *>(keydata1);
  const CryptodProviderKey *key2 = static_cast<const CryptodProviderKey *>(keydata2);

  if (key1 == NULL || key2 == NULL) {
    return OSSL_ERR;
  }

  if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
    return OSSL_OK;
  }

  return key1->key_label_ == key2->key_label_;
}

static void *cdp_cryptod_keyid_dup(const void *keydata_from, int selection) {
  const CryptodProviderKey *source =
      static_cast<const CryptodProviderKey *>(keydata_from);

  if (source == NULL || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
    return NULL;
  }

  return new CryptodProviderKey(source->provider_, source->key_label_, source->key_handle_);
}

static const char *cdp_cryptod_keyid_query_operation_name(int operation_id) {
  if (operation_id == OSSL_OP_SIGNATURE) {
    return "HMAC";
  }
  return NULL;
}

extern const OSSL_DISPATCH cdp_cryptod_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))cdp_cryptod_keyid_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))cdp_cryptod_keyid_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))cdp_cryptod_keyid_load},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))cdp_cryptod_keyid_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
     (void (*)(void))cdp_cryptod_keyid_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))cdp_cryptod_keyid_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))cdp_cryptod_keyid_match},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))cdp_cryptod_keyid_dup},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
     (void (*)(void))cdp_cryptod_keyid_query_operation_name},
    {0, NULL}};

} // extern "C"