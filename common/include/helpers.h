// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>

static std::string hexToString(const std::vector<uint8_t> &val)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : val)
    {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

static std::vector<uint8_t> load_file(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
}

static void dumpHex(const std::string txt, const std::vector<uint8_t> &val)
{
    std::cout << txt << ": ";
    for (auto b : val)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;

    std::cout << std::endl;
}

static void dumpHex(const std::string txt, const void* data, size_t len)
{
    std::cout << txt << ": ";
    for (size_t i=0; i<len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(((uint8_t*)data)[i]);

    std::cout << std::endl;
}

static std::vector<uint8_t> stringToVector(const std::string &input)
{
    std::vector<uint8_t> ret;
    ret.reserve(input.size() / 2);
    for (size_t i = 0; i + 1 < input.size(); i += 2)
    {
        uint8_t byte = static_cast<uint8_t>(std::stoul(input.substr(i, 2), nullptr, 16));
        ret.push_back(byte);
    }
    return ret;
}

static bool compareHex(const std::vector<uint8_t> &val, const std::vector<uint8_t> &expected_val)
{
    bool match = (val.size() == expected_val.size()) &&
                 std::equal(val.begin(), val.end(), expected_val.begin());
    return match;
}
