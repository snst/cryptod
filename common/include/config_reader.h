// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <cctype>
#include "secure_vector.h"
#include "crypto_exception.h"

class ConfigReader
{
private:
    std::unordered_map<std::string, std::string> data;

    // Helper: trim whitespace
    static std::string trim(const std::string &s)
    {
        size_t start = s.find_first_not_of(" \t\r\n");
        size_t end = s.find_last_not_of(" \t\r\n");
        return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
    }

public:
    // Load key=value config file
    void load(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file)
            throw CryptoException(crypto_code_t::NOT_FOUND, "File not found: " + filename);

        std::string line;
        while (std::getline(file, line))
        {
            line = trim(line);
            if (line.empty() || line[0] == '#')
                continue;

            auto pos = line.find('=');
            if (pos == std::string::npos)
                continue;

            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));
            data[key] = value;
        }
    }

    const std::string getString(const std::string &key) const
    {
        auto it = data.find(key);
        if (it != data.end())
        {
            return it->second;
        }
        throw CryptoException(crypto_code_t::NOT_FOUND, "Config value not found: " + key);
    }

    const std::string getString(const std::string &key, const std::string &defaultValue) const
    {
        try
        {
            return getString(key);
        }
        catch (const CryptoException &e)
        {
            if (e.reason() == crypto_code_t::NOT_FOUND)
            {
                return defaultValue;
            }
            else
            {
                throw;
            }
        }
    }

    int getInt(const std::string &key) const
    {
        auto it = data.find(key);
        if (it != data.end())
        {
            try
            {
                return std::stoi(it->second);
            }
            catch (...)
            {
                throw CryptoException(crypto_code_t::NOT_FOUND, "Invalid config value for: " + key);
            }
        }
        throw CryptoException(crypto_code_t::NOT_FOUND, "Config value not found: " + key);
    }

    int getInt(const std::string &key, int defaultValue) const
    {
        try
        {
            return getInt(key);
        }
        catch (const CryptoException &e)
        {
            if (e.reason() == crypto_code_t::NOT_FOUND)
            {
                return defaultValue;
            }
            else
            {
                throw;
            }
        }
    }

    // Convert hex string to secure vector
    const SecureVector getHex(const std::string &key) const
    {
        auto it = data.find(key);
        if (it == data.end())
            throw CryptoException(crypto_code_t::NOT_FOUND, "Value not found: " + key);

        const std::string &hex = it->second;
        if (hex.size() % 2 != 0)
            throw CryptoException(crypto_code_t::NOT_FOUND, "Invalid value for: " + key);

        SecureVector vec;
        vec.reserve(hex.size() / 2);

        for (size_t i = 0; i < hex.size(); i += 2)
        {
            auto hex_pair = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(hex_pair, nullptr, 16));
            vec.push_back(byte);
        }

        return std::move(vec);
    }

    // Optional: check if key exists
    bool hasKey(const std::string &key) const
    {
        return data.find(key) != data.end();
    }
};
