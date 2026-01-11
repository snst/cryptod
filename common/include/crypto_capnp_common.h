// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "crypto_types.h"
#include "crypto_globals.h"
#include "crypto.capnp.h"

#define CRYPTOD_SOCKET_RPC "unix:" CRYPTOD_SOCKET_PATH

static ::CryptoService::HashMode to_crypto_hash_alg(crypto_hash_alg_t mode)
{
    switch (mode)
    {
    case HASH_ALG_NONE:
        return ::CryptoService::HashMode::NONE;
    case HASH_ALG_SHA1:
        return ::CryptoService::HashMode::SHA1;
    case HASH_ALG_SHA224:
        return ::CryptoService::HashMode::SHA224;
    case HASH_ALG_SHA256:
        return ::CryptoService::HashMode::SHA256;
    case HASH_ALG_SHA384:
        return ::CryptoService::HashMode::SHA384;
    case HASH_ALG_SHA512:
        return ::CryptoService::HashMode::SHA512;
    default:
        return ::CryptoService::HashMode::INVALID;
    }
}

static crypto_hash_alg_t to_capnp_hash_mode(::CryptoService::HashMode mode)
{
    switch (mode)
    {
    case ::CryptoService::HashMode::NONE:
        return HASH_ALG_NONE;
    case ::CryptoService::HashMode::SHA1:
        return HASH_ALG_SHA1;
    case ::CryptoService::HashMode::SHA224:
        return HASH_ALG_SHA224;
    case ::CryptoService::HashMode::SHA256:
        return HASH_ALG_SHA256;
    case ::CryptoService::HashMode::SHA384:
        return HASH_ALG_SHA384;
    case ::CryptoService::HashMode::SHA512:
        return HASH_ALG_SHA512;
    default:
        return HASH_ALG_INVALID;
    }
}
