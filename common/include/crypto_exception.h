// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdexcept>
#include <string>

class CryptoException : public std::runtime_error
{
public:
    enum class Reason
    {
        FileNotFound,
        PermissionDenied,
        SyntaxError,
        MissingKey,
        InvalidValue,
        ValueNotFound,
        General,
        Socket,
        Crypto,
    };

    CryptoException(Reason r, std::string message)
        : std::runtime_error(std::move(message)), reason_(r) {}

    Reason reason() const noexcept { return reason_; }

private:
    Reason reason_;
};
