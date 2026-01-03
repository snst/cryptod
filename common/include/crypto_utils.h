// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "crypto_types.h"

static size_t crypto_hash_alg_to_size(crypto_hash_alg_t alg)
{
    switch (alg)
    {
        //        case HASH_ALG_MD5:           return 16;
    case HASH_ALG_SHA1:
        return 20;
    case HASH_ALG_SHA224:
        return 28;
    case HASH_ALG_SHA256:
        return 32;
    case HASH_ALG_SHA384:
        return 48;
    case HASH_ALG_SHA512:
        return 64;
        //        case CRYPTO_HASH_SHA3_224:      return 28;
        //        case CRYPTO_HASH_SHA3_256:      return 32;
        //        case CRYPTO_HASH_SHA3_384:      return 48;
        //        case CRYPTO_HASH_SHA3_512:      return 64;
    case HASH_ALG_INVALID:
        return 0;
    case HASH_ALG_NONE:
        return 0;
    default:
        return 0;
    }
}

static bool safe_strncmp(const char *s1, size_t len1, const char *s2)
{
    size_t len2 = strlen(s2);
    if (len1 != len2)
        return 0; // lengths must match exactly
    return strncmp(s1, s2, len1) == 0;
}

static crypto_hash_alg_t hash_alg_from_string(const char *val, size_t len)
{
    crypto_hash_alg_t ret = HASH_ALG_INVALID;
    if (!val || (len == 0UL))
    {
        ret = HASH_ALG_INVALID;
    }
    else if (safe_strncmp(val, len, "SHA1"))
    {
        ret = HASH_ALG_SHA1;
    }
    else if (safe_strncmp(val, len, "SHA224"))
    {
        ret = HASH_ALG_SHA224;
    }
    else if (safe_strncmp(val, len, "SHA256"))
    {
        ret = HASH_ALG_SHA256;
    }
    else if (safe_strncmp(val, len, "SHA384"))
    {
        ret = HASH_ALG_SHA384;
    }
    else if (safe_strncmp(val, len, "SHA512"))
    {
        ret = HASH_ALG_SHA512;
    }
    return ret;
}
