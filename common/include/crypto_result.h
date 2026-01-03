// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "secure_vector.h"
#include <cstdint>
#include <utility>

enum class ResultStatus : uint32_t
{
    Ok = 0,
    NotFound,
    PermissionDenied,
    InvalidKey,
    CryptoError,
    IOError,
    Unknown
};

class Result
{
public:
    Result() : status(ResultStatus::Unknown) {}
    Result(ResultStatus theStatus, SecureVector theData = {})
        : status(theStatus), data(std::move(theData)) {}

    bool ok() const noexcept { return status == ResultStatus::Ok; }
    void setStatus(ResultStatus theStatus) noexcept { status = theStatus; }
    void setData(SecureVector &&theData) noexcept { data = std::move(theData); }

    ResultStatus status;
    SecureVector data;
};
