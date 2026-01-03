// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <vector>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <stdint.h>

class SecureVector
{
public:
    // Default constructor
    SecureVector() = default;

    // Size constructor
    explicit SecureVector(size_t n) : data_(n) {}

    // Size + value constructor
    SecureVector(size_t n, uint8_t val) : data_(n, val) {}

    // Construct from raw array
    template <size_t N>
    SecureVector(const uint8_t (&arr)[N]) : data_(arr, arr + N) {}

    // Construct from std::array
    template <size_t N>
    SecureVector(const std::array<uint8_t, N> &arr) : data_(arr.begin(), arr.end()) {}

    // Construct from std::vector
    SecureVector(const std::vector<uint8_t> &v) : data_(v) {}
    SecureVector(std::vector<uint8_t> &&v) : data_(std::move(v)) {}

    // Construct from initializer list
    SecureVector(std::initializer_list<uint8_t> init) : data_(init) {}

    // Destructor: zero memory
    ~SecureVector() { secureZero(); }

    // Copy / Move
    SecureVector(const SecureVector &other) = default;
    SecureVector(SecureVector &&other) noexcept = default;
    SecureVector &operator=(const SecureVector &other) = default;
    SecureVector &operator=(SecureVector &&other) noexcept = default;

    // Access
    size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }
    uint8_t *data() noexcept { return data_.data(); }
    const uint8_t *data() const noexcept { return data_.data(); }
    uint8_t &operator[](size_t i) { return data_[i]; }
    const uint8_t &operator[](size_t i) const { return data_[i]; }

    // Modify
    void push_back(uint8_t val) { data_.push_back(val); }
    void resize(size_t n)
    {
        if (n < data_.size())
            secureZero(data_.data() + n, data_.size() - n);
        data_.resize(n);
    }
    void clear()
    {
        secureZero();
        data_.clear();
    }
    void assign(size_t n, uint8_t val)
    {
        secureZero();
        data_.assign(n, val);
    }
    void reserve(size_t n) { data_.reserve(n); }

    std::vector<uint8_t> &vector() { return data_; }

    // -------------------------
    // Constant-time comparison
    // -------------------------
    friend bool operator==(const SecureVector &a,
                           const SecureVector &b) noexcept
    {
        if (a.data_.size() != b.data_.size())
            return false;

        uint8_t diff = 0;
        for (size_t i = 0; i < a.data_.size(); ++i)
            diff |= a.data_[i] ^ b.data_[i];

        return diff == 0;
    }

    friend bool operator!=(const SecureVector &a,
                           const SecureVector &b) noexcept
    {
        return !(a == b);
    }

private:
    std::vector<uint8_t> data_;

    void secureZero() { secureZero(data_.data(), data_.size()); }

    void secureZero(uint8_t *ptr, size_t n)
    {
        if (ptr && n > 0)
        {
            volatile uint8_t *p = ptr;
            for (size_t i = 0; i < n; ++i)
                p[i] = 0;
        }
    }
};
