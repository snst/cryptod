// Common test utilities
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cryptod {
namespace test {

/// Convert a hex string to bytes.
inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

} // namespace test
} // namespace cryptod
