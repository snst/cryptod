// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "cryptod/client.hpp"
#include <openssl/core.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#define OSSL_OK 1
#define OSSL_ERR 0

#define LOG_DEBUG(fmt, ...)
// #define LOG_INFO(fmt, ...)
// #define LOG_ERROR(fmt, ...)
#define LOG_ENTRY(fmt, ...)
#define LOG_EXIT(fmt, ...)
// #define LOG_EXCEPTION(e)

#ifndef LOG_DEBUG
#define LOG_DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#endif

#ifndef LOG_INFO
#define LOG_INFO(fmt, ...) fprintf(stderr, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#endif

#ifndef LOG_ERROR
#define LOG_ERROR(fmt, ...)                                                    \
  fprintf(stderr, "[ERROR] %s() : " fmt "\n", __func__, ##__VA_ARGS__)
#endif

#ifndef LOG_ENTRY
#define LOG_ENTRY(fmt, ...)                                                    \
  fprintf(stderr, "[INFO]  +++ %s() " fmt "\n", __func__, ##__VA_ARGS__)
#endif

#ifndef LOG_EXIT
#define LOG_EXIT(fmt, ...)                                                     \
  fprintf(stderr, "[INFO]  --- %s() " fmt "\n", __func__, ##__VA_ARGS__)
#endif

#ifndef LOG_EXCEPTION
#define LOG_EXCEPTION(e) fprintf(stderr, "[ERROR] %s\n", e)
#endif

static constexpr const char *CRYPTOD_SOCKET = "/tmp/cryptod.sock";
static constexpr const char *CRYPTOD_STORE_SCHEME = "cryptod";
static constexpr const char *CRYPTOD_SYM_KEY_TYPE = "CRYPTOD-SYMKEY";

class CryptodProviderContext;

class CryptodProviderKey {
public:
  CryptodProviderKey(CryptodProviderContext *provider)
      : provider_(provider) {}
  explicit CryptodProviderKey(CryptodProviderContext *provider, std::string key_label,
                              cryptod::KeyHandle key_handle)
      : provider_(provider), key_label_(std::move(key_label)),
        key_handle_(std::move(key_handle)) {}
  explicit CryptodProviderKey(CryptodProviderContext *provider,
                              std::string key_label)
      : provider_(provider), key_label_(std::move(key_label)) {}

  bool is_loaded() {
    return key_handle_.id() != 0;
  }

  bool has_label() {
    return !key_label_.empty();
  }

  bool load();

  CryptodProviderContext *provider_;
  std::string key_label_;
  cryptod::KeyHandle key_handle_;
};

class CryptodProviderContext {
public:
  std::unique_ptr<cryptod::Client> client_;

  void disconnect();
  bool connect();
  bool load_key(CryptodProviderKey *key);
  bool load_key(const std::string& key_label, cryptod::KeyHandle& key_handle);
  std::unique_ptr<cryptod::MacContext> mac_init(cryptod::MacAlgorithm algorithm, const cryptod::KeyHandle& key);
};


class CryptodStoreContext {
public:
  explicit CryptodStoreContext(CryptodProviderContext *provider,
                              std::string key_label)
      : provider_(provider), key_label_(std::move(key_label)) {}

  CryptodProviderContext *provider_;
  std::string key_label_;
};


#define PROV_CTX(x) ((CryptodProviderContext *)x)
#define HMAC_CTX(x) ((CryptodHmacMacContext *)x)
#define PARAM_KEY_LABEL "key_label"
