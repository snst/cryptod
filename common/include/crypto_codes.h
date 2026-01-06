// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stddef.h>

typedef enum
{
    OK = 0,
    KEY_NOT_FOUND = 1,
    NO_ACCESS = 2,
    OP_NOT_PERMITTED = 3,
    CORRUPTED_RESPONSE = 4,
    UNEXPECTED_RESPONSE = 5,
    COM_ERROR = 6,
    ERROR = 7,
    UNSUPPORTED = 8,
    CRYPTO_ERROR = 9,
    NOT_FOUND = 10,
    INVALID_VALUE = 11,
} crypto_code_t;

static const char *cc_to_str(crypto_code_t code)
{
    switch (code)
    {
    case OK:
        return "OK";
    case KEY_NOT_FOUND:
        return "KEY_NOT_FOUND";
    case NO_ACCESS:
        return "NO_ACCESS";
    case OP_NOT_PERMITTED:
        return "OP_NOT_PERMITTED";
    case CORRUPTED_RESPONSE:
        return "CORRUPTED_RESPONSE";
    case UNEXPECTED_RESPONSE:
        return "UNEXPECTED_RESPONSE";
    case COM_ERROR:
        return "COM_ERROR";
    case ERROR:
        return "ERROR";
    case UNSUPPORTED:
        return "UNSUPPORTED";
    case CRYPTO_ERROR:
        return "CRYPTO_ERROR";
    case NOT_FOUND:
        return "NOT_FOUND";
    case INVALID_VALUE:
        return "INVALID_VALUE";
    default:
        return "UNKOWN ERROR CODE";
    }
}