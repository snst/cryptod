// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdexcept>
#include <string>
#include "crypto_codes.h"

class CryptoException : public std::runtime_error
{
public:
    CryptoException(crypto_code_t r, std::string message)
        : std::runtime_error(std::move(message)), reason_(r) {}

    crypto_code_t reason() const noexcept { return reason_; }

private:
    crypto_code_t reason_;
};
