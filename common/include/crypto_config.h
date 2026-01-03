// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include "config_reader.h"
#include "crypto_exception.h"

#define ENABLE_LOGGING
#include "log_macro.h"

class CryptoConfig
{
public:
    void load(const std::string &filename)
    {
        LOG_INFO("Loading config: %s", filename.c_str());
        reader_.load(filename);
    }

    const SecureVector masterKey()
    {
        return reader_.getHex("masterkey");
    }

    const std::string keystoreFile()
    {
        return reader_.getString("keystore");
    }

private:
    ConfigReader reader_;
};
