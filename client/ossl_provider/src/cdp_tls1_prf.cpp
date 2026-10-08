// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "cdp_common.h"
#include "cryptod_provider.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/tls1.h>
#include <optional>
#include <string.h>
#include <vector>

extern "C" {

/* Function Prototypes */
static OSSL_FUNC_kdf_newctx_fn cdp_tls1_prf_newctx;
static OSSL_FUNC_kdf_dupctx_fn cdp_tls1_prf_dupctx;
static OSSL_FUNC_kdf_freectx_fn cdp_tls1_prf_freectx;
static OSSL_FUNC_kdf_reset_fn cdp_tls1_prf_reset;
static OSSL_FUNC_kdf_derive_fn cdp_tls1_prf_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn cdp_tls1_prf_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn cdp_tls1_prf_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn cdp_tls1_prf_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn cdp_tls1_prf_get_ctx_params;

/* KDF context for TLS 1.2 PRF */
class CdpTls1PrfContext {
public:
  CryptodProviderContext *provider_;

  /* Optional custom key object, when secret is provided as a cryptod label */
  std::optional<CryptodProviderKey> key_;

  /* Optional plain text secret if no extended master secret set in key_ */
  std::optional<SecretValue> secret_;

  /* Concatenated seed (label + random values) */
  std::vector<uint8_t> seed_;

  /* Digest algorithm name for reference */
  std::string digest_name_;

  CdpTls1PrfContext(CryptodProviderContext *provider) : provider_(provider) {}
};

static bool safe_strncasecmp(const char *s1, size_t len1, const char *s2) {
  size_t len2 = strlen(s2);
  if (len1 != len2)
    return false;
  return strncasecmp(s1, s2, len1) == 0;
}

static cryptod::KdfAlgorithm
digest_to_kdf_algorithm(const std::string &digest) {

  const char *val = digest.c_str();
  size_t len = digest.size();

  if (safe_strncasecmp(val, len, "SHA256") ||
      safe_strncasecmp(val, len, "SHA-256") ||
      safe_strncasecmp(val, len, "SHA2-256")) {
    return cryptod::KdfAlgorithm::Tls12EmsPrfSha256;
  } else if (safe_strncasecmp(val, len, "SHA384") ||
             safe_strncasecmp(val, len, "SHA-384") ||
             safe_strncasecmp(val, len, "SHA2-384")) {
    return cryptod::KdfAlgorithm::Tls12EmsPrfSha384;
  }

  // Default to SHA256 for unrecognized digests
  return cryptod::KdfAlgorithm::Unspecified;
}

static bool
detect_extended_master_secret_from_seed(const std::vector<uint8_t> &seed) {
  // The seed starts with the label string (without null terminator)
  // Check which label matches the beginning of the seed
  return starts_with(seed.data(), seed.size(),
                     (const uint8_t *)TLS_MD_EXTENDED_MASTER_SECRET_CONST,
                     TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE);
  return false;
}

/* Get a library context with only the default provider loaded */
static OSSL_LIB_CTX *get_default_provider_libctx() {
  static OSSL_LIB_CTX *ctx = nullptr;
  static OSSL_PROVIDER *defprov = nullptr;

  if (ctx == nullptr) {
    ctx = OSSL_LIB_CTX_new();
    if (ctx != nullptr) {
      defprov = OSSL_PROVIDER_load(ctx, "default");
      if (defprov == nullptr) {
        LOG_ERROR("Failed to load default provider into separate libctx");
        OSSL_LIB_CTX_free(ctx);
        ctx = nullptr;
      }
    }
  }
  return ctx;
}

/* Delegate TLS-PRF to OpenSSL's default provider */
static int delegate_to_default_provider(const std::string &digest_name,
                                        const SecretValue &secret,
                                        const std::vector<uint8_t> &seed,
                                        unsigned char *key, size_t keylen) {
  EVP_KDF *kdf = nullptr;
  EVP_KDF_CTX *kctx = nullptr;
  int ret = OSSL_ERR;

  LOG_INFO("delegate_to_default_provider: digest=%s, secret_len=%zu, "
           "seed_len=%zu, keylen=%zu",
           digest_name.c_str(), secret.size(), seed.size(), keylen);

  // Use a separate libctx with only the default provider loaded
  OSSL_LIB_CTX *libctx = get_default_provider_libctx();
  if (libctx == nullptr) {
    LOG_ERROR("Failed to get default provider libctx");
    return OSSL_ERR;
  }

  // Fetch TLS1-PRF from the default provider via the separate libctx
  kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_TLS1_PRF, nullptr);
  if (kdf == nullptr) {
    LOG_ERROR("Failed to fetch TLS1-PRF from default provider");
    goto err;
  }

  kctx = EVP_KDF_CTX_new(kdf);
  if (kctx == nullptr) {
    LOG_ERROR("Failed to create KDF context");
    goto err;
  }

  {
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char *>(digest_name.c_str()), 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SECRET, const_cast<uint8_t *>(secret.data()),
        secret.size());
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SEED, const_cast<uint8_t *>(seed.data()), seed.size());
    params[3] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, key, keylen, params) <= 0) {
      LOG_ERROR("Default provider TLS1-PRF derive failed");
      goto err;
    }
  }

  LOG_INFO("delegate_to_default_provider: success");
  ret = OSSL_OK;

err:
  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);
  return ret;
}

static void *cdp_tls1_prf_newctx(void *provctx) {
  LOG_INFO("cdp_tls1_prf_newctx called");
  CdpTls1PrfContext *ctx = new CdpTls1PrfContext(PROV_CTX(provctx));
  return ctx;
}

static void *cdp_tls1_prf_dupctx(void *vctx) {
  if (!vctx)
    return nullptr;

  CdpTls1PrfContext *src = static_cast<CdpTls1PrfContext *>(vctx);
  CdpTls1PrfContext *dst = new CdpTls1PrfContext(src->provider_);

  dst->provider_ = src->provider_;
  dst->secret_ = src->secret_;
  dst->seed_ = src->seed_;
  dst->digest_name_ = src->digest_name_;

  return dst;
}

static void cdp_tls1_prf_freectx(void *vctx) {
  CdpTls1PrfContext *ctx = static_cast<CdpTls1PrfContext *>(vctx);
  if (ctx) {
    delete ctx;
  }
}

static void cdp_tls1_prf_reset(void *vctx) {
  CdpTls1PrfContext *ctx = static_cast<CdpTls1PrfContext *>(vctx);
  if (ctx) {
    // Clear secret securely
    if (ctx->secret_.has_value()) {
      ctx->secret_->clear();
    }
    ctx->seed_.clear();
    ctx->digest_name_.clear();
    ctx->key_.reset();
  }
}

static int cdp_tls1_prf_derive(void *vctx, unsigned char *key, size_t keylen,
                               const OSSL_PARAM params[]) {
  CdpTls1PrfContext *ctx = static_cast<CdpTls1PrfContext *>(vctx);

  LOG_INFO("cdp_tls1_prf_derive called, keylen=%zu", keylen);

  if (!ctx || !key || keylen == 0) {
    return OSSL_ERR;
  }

  // Apply any params passed during derive
  if (params != nullptr) {
    if (cdp_tls1_prf_set_ctx_params(vctx, params) != OSSL_OK) {
      return OSSL_ERR;
    }
  }

  if (ctx->seed_.empty()) {
    LOG_ERROR("Missing seed for TLS1-PRF");
    return OSSL_ERR;
  }

  // Check if this is a master secret derivation
  // Only master secret derivation goes to cryptod; everything else
  // (key expansion, client/server finished) uses the default provider
  if (!detect_extended_master_secret_from_seed(ctx->seed_)) {

    if (!ctx->secret_.has_value()) {
      LOG_ERROR("Missing secret for TLS1-PRF");
      return OSSL_ERR;
    }
    LOG_INFO("Non-master-secret TLS-PRF, delegating to default provider");
    return delegate_to_default_provider(ctx->digest_name_, ctx->secret_.value(),
                                        ctx->seed_, key, keylen);
  }

  LOG_INFO("Master secret derivation, using cryptod");

  // The seed contains: label_string + randoms
  // We need to strip the label
  size_t label_len = TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE;

  // Extract just the randoms portion (skip the label)
  std::span<const uint8_t> info_random(ctx->seed_.data() + label_len,
                                       ctx->seed_.size() - label_len);

  if (!ctx->key_->load()) {
    LOG_ERROR("Failed to load key %s", ctx->key_->key_label_);
    return OSSL_ERR;
  }

  // Build KDF parameters
  cryptod::KdfParams kdf_params{
      .algorithm = digest_to_kdf_algorithm(ctx->digest_name_),
      .key_handle = ctx->key_->key_handle_,
      .output_len = keylen,
      .salt = std::nullopt,
      .info = info_random, // Just the randoms, no label
      .iterations = std::nullopt,
  };

  try {
    std::vector<uint8_t> derived =
        ctx->provider_->client_->derive_key(kdf_params);

    if (derived.size() != keylen) {
      LOG_ERROR("Derived key length mismatch: expected %zu, got %zu", keylen,
                derived.size());
      return OSSL_ERR;
    }

    memcpy(key, derived.data(), keylen);
    return OSSL_OK;
  } catch (const std::exception &e) {
    LOG_EXCEPTION(e.what());
    return OSSL_ERR;
  }
}

static int cdp_tls1_prf_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  CdpTls1PrfContext *ctx = static_cast<CdpTls1PrfContext *>(vctx);
  const OSSL_PARAM *p;

  if (!ctx || !params) {
    return OSSL_OK; // Nothing to set
  }

  /* Handle digest parameter */
  p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
  if (p != nullptr) {
    if (p->data_type != OSSL_PARAM_UTF8_STRING) {
      return OSSL_ERR;
    }
    ctx->digest_name_ =
        std::string(static_cast<const char *>(p->data), p->data_size);
  }

  /* Handle seed parameter - seeds are concatenated */
  p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
  if (p != nullptr) {
    // Clear existing seeds when new seeds are provided
    ctx->seed_.clear();
  }
  bool is_ems = false;
  while (p != nullptr) {
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
      return OSSL_ERR;
    }
    if (p->data != nullptr && p->data_size > 0) {
      const uint8_t *data = static_cast<const uint8_t *>(p->data);
      ctx->seed_.insert(ctx->seed_.end(), data, data + p->data_size);
      if (p->data_size == TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE &&
          !memcmp(p->data, TLS_MD_EXTENDED_MASTER_SECRET_CONST,
                  TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE)) {
        is_ems = true;
      }
    }
    // Look for next seed parameter
    p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_SEED);
  }

  /* Handle secret parameter */
  p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET);
  if (p != nullptr) {
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
      return OSSL_ERR;
    }
    if (ctx->secret_.has_value()) {
      ctx->secret_->clear();
    }
    ctx->key_.reset();
    if (p->data != nullptr && p->data_size > 0) {
      const uint8_t *data = static_cast<const uint8_t *>(p->data);
      if (is_ems) {
        if (p->data_size < 2) {
          return OSSL_ERR;
        }
        uint16_t label_len = (data[0] << 8) + data[1];
        if (p->data_size != (2 * label_len + 2 * sizeof(uint16_t))) {
          return OSSL_ERR;
        }
        uint16_t label_len2 = (data[label_len + sizeof(uint16_t)] << 8) +
                              data[label_len + sizeof(uint16_t) + 1];
        if (label_len != label_len2) {
          return OSSL_ERR;
        }
        std::string label(reinterpret_cast<const char *>(
                              data + label_len + (2 * sizeof(uint16_t))),
                          label_len);
        CryptodProviderKey k(ctx->provider_, std::move(label));
        ctx->key_.emplace(k);
      }

      if (!is_ems) {
        SecretValue s;
        ctx->secret_ = s;
        ctx->secret_->assign(data, p->data_size);
      }
    }
  }

  return OSSL_OK;
}

static const OSSL_PARAM *cdp_tls1_prf_settable_ctx_params(void *vctx,
                                                          void *provctx) {
  static const OSSL_PARAM known_settable_ctx_params[] = {
      OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
      OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0), OSSL_PARAM_END};
  return known_settable_ctx_params;
}

static int cdp_tls1_prf_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  OSSL_PARAM *p;

  p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
  if (p != nullptr) {
    // TLS-PRF can produce arbitrary length output
    if (!OSSL_PARAM_set_size_t(p, SIZE_MAX)) {
      return OSSL_ERR;
    }
  }

  return OSSL_OK;
}

static const OSSL_PARAM *cdp_tls1_prf_gettable_ctx_params(void *vctx,
                                                          void *provctx) {
  static const OSSL_PARAM known_gettable_ctx_params[] = {
      OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL), OSSL_PARAM_END};
  return known_gettable_ctx_params;
}

/* Dispatch Table for TLS1-PRF KDF */
extern const OSSL_DISPATCH cdp_tls1_prf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))cdp_tls1_prf_newctx},
    {OSSL_FUNC_KDF_DUPCTX, (void (*)(void))cdp_tls1_prf_dupctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))cdp_tls1_prf_freectx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))cdp_tls1_prf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))cdp_tls1_prf_derive},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
     (void (*)(void))cdp_tls1_prf_settable_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))cdp_tls1_prf_set_ctx_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
     (void (*)(void))cdp_tls1_prf_gettable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))cdp_tls1_prf_get_ctx_params},
    {0, NULL}};

} // extern "C"
