// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <openssl/core.h>
#include "crypto_types.h"

bool parse_key(void *input, size_t len, uint32_t *key_out);
