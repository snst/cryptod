// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "secure_vector.h"
#include <cstdint>
#include <utility>
#include "crypto_codes.h"

class Result
{
public:
    Result() : status(crypto_code_t::ERROR) {}
    Result(crypto_code_t theStatus, SecureVector theData = {})
        : status(theStatus), data(std::move(theData)) {}

    bool ok() const noexcept { return status == crypto_code_t::OK; }
    void setStatus(crypto_code_t theStatus) noexcept { status = theStatus; }
    void setData(SecureVector &&theData) noexcept { data = std::move(theData); }

    crypto_code_t status;
    SecureVector data;
};
