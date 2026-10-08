// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "cryptod_provider.h"

#include <cstring>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

extern "C" {

static OSSL_FUNC_mac_newctx_fn cdp_hmac_mac_newctx;
static OSSL_FUNC_mac_freectx_fn cdp_hmac_mac_freectx;
static OSSL_FUNC_mac_dupctx_fn cdp_hmac_mac_dupctx;
static OSSL_FUNC_mac_init_fn cdp_hmac_mac_init;
static OSSL_FUNC_mac_update_fn cdp_hmac_mac_update;
static OSSL_FUNC_mac_final_fn cdp_hmac_mac_final;
static OSSL_FUNC_mac_get_ctx_params_fn cdp_hmac_mac_get_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn cdp_hmac_mac_set_ctx_params;
static OSSL_FUNC_mac_gettable_ctx_params_fn cdp_hmac_mac_gettable_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn cdp_hmac_mac_settable_ctx_params;

enum SelectedProvider {
  NOT_SELECTED = 0,
  DEFAULT_PROVIDER = 1,
  CRYPTOD_PROVIDER = 2
};

class CryptodHmacMacContext {
public:
  CryptodProviderContext *provider_;
  SelectedProvider selected_;
  CryptodProviderKey key_;
  cryptod::MacAlgorithm mac_alg_;
  std::unique_ptr<cryptod::MacContext> cryptod_hmac_;
  EVP_MAC_CTX *default_hmac_;

  CryptodHmacMacContext(CryptodProviderContext *provider)
      : provider_(provider), selected_(NOT_SELECTED), key_(provider),
        mac_alg_(cryptod::MacAlgorithm::Unspecified), default_hmac_(NULL) {}

  ~CryptodHmacMacContext() {
    if (default_hmac_) {
      EVP_MAC_CTX_free(default_hmac_);
      default_hmac_ = nullptr;
    }
  }
};

static bool safe_strncmp_mac(const char *s1, size_t len1, const char *s2) {
  size_t len2 = strlen(s2);
  if (len1 != len2)
    return false;
  return strncmp(s1, s2, len1) == 0;
}

static cryptod::MacAlgorithm digest_name_to_mac_alg(const char *val,
                                                    size_t len) {
  if (val == NULL || len == 0) {
    return cryptod::MacAlgorithm::HmacSha256;
  }
  if (safe_strncmp_mac(val, len, "SHA1"))
    return cryptod::MacAlgorithm::HmacSha1;
  if (safe_strncmp_mac(val, len, "SHA224"))
    return cryptod::MacAlgorithm::HmacSha224;
  if (safe_strncmp_mac(val, len, "SHA256"))
    return cryptod::MacAlgorithm::HmacSha256;
  if (safe_strncmp_mac(val, len, "SHA384"))
    return cryptod::MacAlgorithm::HmacSha384;
  if (safe_strncmp_mac(val, len, "SHA512"))
    return cryptod::MacAlgorithm::HmacSha512;
  return cryptod::MacAlgorithm::Unspecified;
}

static const char *mac_alg_to_digest_name(cryptod::MacAlgorithm alg) {
  switch (alg) {
  case cryptod::MacAlgorithm::HmacSha1:
    return "SHA1";
  case cryptod::MacAlgorithm::HmacSha224:
    return "SHA224";
  case cryptod::MacAlgorithm::HmacSha256:
    return "SHA256";
  case cryptod::MacAlgorithm::HmacSha384:
    return "SHA384";
  case cryptod::MacAlgorithm::HmacSha512:
    return "SHA512";
  default:
    return "";
  }
}

static size_t mac_alg_output_size(cryptod::MacAlgorithm alg) {
  switch (alg) {
  case cryptod::MacAlgorithm::HmacSha1:
    return 20;
  case cryptod::MacAlgorithm::HmacSha224:
    return 28;
  case cryptod::MacAlgorithm::HmacSha256:
    return 32;
  case cryptod::MacAlgorithm::HmacSha384:
    return 48;
  case cryptod::MacAlgorithm::HmacSha512:
    return 64;
  default:
    return 0;
  }
}

static void *cdp_hmac_mac_newctx(void *provctx) {
  auto *ctx = new CryptodHmacMacContext(PROV_CTX(provctx));
  return ctx;
}

static void cdp_hmac_mac_freectx(void *vctx) {
  auto *ctx = HMAC_CTX(vctx);
  delete ctx;
}

static void *cdp_hmac_mac_dupctx(void *vctx) {
  auto *source = HMAC_CTX(vctx);
  if (source == NULL) {
    return NULL;
  }

  auto *copy = new CryptodHmacMacContext(source->provider_);
  copy->key_ = source->key_;
  copy->mac_alg_ = source->mac_alg_;
  copy->selected_ = source->selected_;

  if (source->selected_ == SelectedProvider::DEFAULT_PROVIDER &&
      source->default_hmac_ != NULL) {
    copy->default_hmac_ = EVP_MAC_CTX_dup(source->default_hmac_);
    if (copy->default_hmac_ == NULL) {
      delete copy;
      return NULL;
    }
  } else if (source->selected_ == SelectedProvider::CRYPTOD_PROVIDER &&
             source->key_.is_loaded()) {
    copy->cryptod_hmac_ =
        copy->provider_->mac_init(copy->mac_alg_, copy->key_.key_handle_);
    if (!copy->cryptod_hmac_) {
      delete copy;
      return NULL;
    }
  }

  return copy;
}

static int cdp_hmac_default_init(CryptodHmacMacContext *ctx,
                                 const char *digest_name,
                                 const unsigned char *key, size_t keylen) {

  if (!key || keylen == 0) {
    return OSSL_ERR;
  }

  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", "provider!=cryptod");
  if (!mac) {
    return OSSL_ERR;
  }
  ctx->default_hmac_ = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);

  if (!ctx->default_hmac_) {
    return OSSL_ERR;
  }

  if (!digest_name) {
    digest_name = mac_alg_to_digest_name(ctx->mac_alg_);
  }

  OSSL_PARAM local_params[2];
  local_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                     (char *)digest_name, 0);
  local_params[1] = OSSL_PARAM_construct_end();

  if (!EVP_MAC_init(ctx->default_hmac_, key, keylen, local_params)) {
    EVP_MAC_CTX_free(ctx->default_hmac_);
    ctx->default_hmac_ = nullptr;
    return OSSL_ERR;
  }
  return OSSL_OK;
}

static int cdp_hmac_mac_init(void *vctx, const unsigned char *key,
                             size_t keylen, const OSSL_PARAM params[]) {
  auto *ctx = HMAC_CTX(vctx);
  if (ctx == NULL) {
    return OSSL_ERR;
  }

  const char *digest_name = NULL;
  ctx->selected_ = SelectedProvider::NOT_SELECTED;

  // Process parameters to extract digest algorithm and key label
  if (params != NULL) {
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
      if (strcmp(p->key, OSSL_MAC_PARAM_DIGEST) == 0) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
          ctx->mac_alg_ = digest_name_to_mac_alg(
              static_cast<const char *>(p->data), p->data_size);
          digest_name = (const char *)p->data;
        }
      } else if (strcmp(p->key, PARAM_KEY_LABEL) == 0) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING && p->data != NULL &&
            p->data_size > 0) {
          ctx->key_.key_label_ =
              std::string(static_cast<const char *>(p->data), p->data_size);
        }
      }
    }
  }

  if (!ctx->key_.has_label()) { // no key label provided => use default impl
    int ret = cdp_hmac_default_init(ctx, digest_name, key, keylen);
    if (OSSL_OK == ret) {
      ctx->selected_ = SelectedProvider::DEFAULT_PROVIDER;
    }
    return ret;
  } else { // use cryptod impl
    bool ret = ctx->key_.load();
    if (ret && ctx->key_.is_loaded()) {
      ctx->cryptod_hmac_ =
          ctx->provider_->mac_init(ctx->mac_alg_, ctx->key_.key_handle_);
      if (ctx->cryptod_hmac_) {
        ctx->selected_ = SelectedProvider::CRYPTOD_PROVIDER;
        return OSSL_OK;
      }
    }
  }

  return OSSL_ERR;
}

static int cdp_hmac_mac_update(void *vctx, const unsigned char *data,
                               size_t datalen) {
  auto *ctx = HMAC_CTX(vctx);
  if (ctx == NULL) {
    return OSSL_ERR;
  }

  if (ctx->selected_ == SelectedProvider::CRYPTOD_PROVIDER) {
    ctx->cryptod_hmac_->update(data, datalen);
  } else if (ctx->selected_ == SelectedProvider::DEFAULT_PROVIDER &&
             ctx->default_hmac_ != NULL) {
    if (!EVP_MAC_update(ctx->default_hmac_, data, datalen)) {
      return OSSL_ERR;
    }
  }
  return OSSL_OK;
}

static int cdp_hmac_mac_final(void *vctx, unsigned char *out, size_t *outlen,
                              size_t outsize) {
  auto *ctx = HMAC_CTX(vctx);
  if (ctx == NULL || outlen == NULL) {
    return OSSL_ERR;
  }

  const size_t expected_len = mac_alg_output_size(ctx->mac_alg_);
  if (out == NULL) {
    *outlen = expected_len;
    return OSSL_OK;
  }
  if (outsize < expected_len) {
    return OSSL_ERR;
  }

  if (ctx->selected_ == SelectedProvider::CRYPTOD_PROVIDER) {
    auto computed_hmac = ctx->cryptod_hmac_->finish();
    memcpy(out, computed_hmac.data(), computed_hmac.size());
    *outlen = computed_hmac.size();
  } else if (ctx->selected_ == SelectedProvider::DEFAULT_PROVIDER &&
             ctx->default_hmac_ != NULL) {
    size_t mac_len = 0;
    if (!EVP_MAC_final(ctx->default_hmac_, out, &mac_len, outsize)) {
      return OSSL_ERR;
    }
    *outlen = mac_len;
  }
  return OSSL_OK;
}

static int cdp_hmac_mac_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  auto *ctx = HMAC_CTX(vctx);
  if (ctx == NULL || params == NULL) {
    return OSSL_ERR;
  }

  for (OSSL_PARAM *p = params; p->key != NULL; p++) {
    if (strcmp(p->key, OSSL_MAC_PARAM_SIZE) == 0) {
      size_t size = mac_alg_output_size(ctx->mac_alg_);
      if (!OSSL_PARAM_set_size_t(p, size)) {
        return OSSL_ERR;
      }
    }
  }
  return OSSL_OK;
}

static int cdp_hmac_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  auto *ctx = HMAC_CTX(vctx);
  if (ctx == NULL) {
    return OSSL_ERR;
  }

  if (params == NULL) {
    return OSSL_OK;
  }

  for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
    if (strcmp(p->key, OSSL_MAC_PARAM_DIGEST) == 0) {
      if (p->data_type == OSSL_PARAM_UTF8_STRING) {
        ctx->mac_alg_ = digest_name_to_mac_alg(
            static_cast<const char *>(p->data), p->data_size);
      }
    } 
    else if (strcmp(p->key, PARAM_KEY_LABEL) == 0) {
      if (p->data_type == OSSL_PARAM_UTF8_STRING && p->data != NULL &&
          p->data_size > 0) {
        ctx->key_.key_label_ =
            std::string(static_cast<const char *>(p->data), p->data_size);
      }
    }
  }

  return OSSL_OK;
}

static const OSSL_PARAM *cdp_hmac_mac_gettable_ctx_params(void *vctx,
                                                          void *provctx) {
  static const OSSL_PARAM gettable[] = {
      OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL), OSSL_PARAM_END};
  return gettable;
}

static const OSSL_PARAM *cdp_hmac_mac_settable_ctx_params(void *vctx,
                                                          void *provctx) {
  static const OSSL_PARAM settable[] = {
      OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_utf8_string(PARAM_KEY_LABEL, NULL, 0), OSSL_PARAM_END};
  return settable;
}

extern const OSSL_DISPATCH cdp_hmac_mac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))cdp_hmac_mac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))cdp_hmac_mac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))cdp_hmac_mac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))cdp_hmac_mac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))cdp_hmac_mac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))cdp_hmac_mac_final},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))cdp_hmac_mac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))cdp_hmac_mac_set_ctx_params},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
     (void (*)(void))cdp_hmac_mac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
     (void (*)(void))cdp_hmac_mac_settable_ctx_params},
    {0, NULL}};

} // extern "C"
