// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <cstring>
#include <stdint.h>
#include <string>
#include <vector>

inline bool starts_with(const uint8_t *data, size_t len, const uint8_t *pattern,
                        size_t pattern_len) {

  if (len < pattern_len)
    return false;
  return memcmp(data, pattern, pattern_len) == 0;
};

class SecretValue {
public:
  // Default constructor
  SecretValue() = default;
  ~SecretValue() { clear(); }
  void clear() {
    if (!data_.empty()) {
      explicit_bzero(data_.data(), data_.size());
    }
  }

  void assign(const uint8_t *ptr, std::size_t len) {
    clear();
    if (ptr && len > 0) {
      data_.assign(ptr, ptr + len);
    }
  }

  uint8_t *data() { return data_.data(); }
  const uint8_t *data() const { return data_.data(); }

  std::size_t size() const { return data_.size(); }
  bool empty() const { return data_.empty(); }

private:
  std::vector<uint8_t> data_;
};
