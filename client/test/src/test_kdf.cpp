// KDF tests - TLS 1.2 PRF

#include <gtest/gtest.h>
#include "cryptod/client.hpp"
#include "cryptod/kdf.hpp"
#include "test_utils.hpp"

#if 0

namespace cryptod {
namespace {

using test::hex_to_bytes;

class KdfTest : public ::testing::Test {
protected:
    static constexpr const char* TEST_SOCKET = "/tmp/cryptod.sock";
    
    // Skip tests if daemon not running
    static bool daemon_available() {
        try {
            auto client = Client::connect(TEST_SOCKET);
            return true;
        } catch (...) {
            return false;
        }
    }
};

// Test TLS 1.2 PRF master secret derivation with SHA-256
// Uses the same test vectors as the Rust implementation
TEST_F(KdfTest, Tls12PrfMasterSecret) {
    auto client = Client::connect(TEST_SOCKET);
    
    // Pre-master secret (48 bytes of 0x03)
    std::vector<uint8_t> pre_master_secret(48, 0x03);
    
    // Client random (32 bytes: 0x00 to 0x1f)
    std::vector<uint8_t> client_random;
    for (uint8_t i = 0; i < 32; ++i) {
        client_random.push_back(i);
    }
    
    // Server random (32 bytes: 0x20 to 0x3f)
    std::vector<uint8_t> server_random;
    for (uint8_t i = 0x20; i < 0x40; ++i) {
        server_random.push_back(i);
    }
    
    // Seed = client_random + server_random
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), client_random.begin(), client_random.end());
    seed.insert(seed.end(), server_random.begin(), server_random.end());
    
    // Create KDF params for master secret derivation
    auto params = KdfParams::tls12_master_secret(pre_master_secret, seed);
    
    auto master_secret = client->derive_key(params);
    
    // Expected master secret (computed using Python HMAC reference implementation)
    auto expected = hex_to_bytes(
        "f999ac25af645ede262f9d6775579fdc"
        "3dbd8fb3a21e11776773ca011d06e223"
        "1884dbaa87119abb63945be6393ef598"
    );
    
    EXPECT_EQ(master_secret.size(), 48);
    EXPECT_EQ(master_secret, expected);
}

TEST_F(KdfTest, Tls12PrfMasterSecret2) {
    auto client = Client::connect(TEST_SOCKET);
    
    // Pre-master secret (48 bytes of 0x03)
    std::vector<uint8_t> pre_master_secret(48, 0x03);

    auto client_random = hex_to_bytes(
        "0001020304050607" \
        "08090a0b0c0d0e0f" \
        "1011121314151617" \
        "18191a1b1c1d1e1f"
    );
    
    auto server_random = hex_to_bytes(
        "2021222324252627" \
        "28292a2b2c2d2e2f" \
        "3031323334353637" \
        "38393a3b3c3d3e3f"
    );
    
    // Seed = client_random + server_random
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), client_random.begin(), client_random.end());
    seed.insert(seed.end(), server_random.begin(), server_random.end());
    
    // Create KDF params for master secret derivation
    auto params = KdfParams::tls12_master_secret(pre_master_secret, seed);
    
    auto master_secret = client->derive_key(params);
    
    // Expected master secret (computed using Python HMAC reference implementation)
    auto expected = hex_to_bytes(
        "f999ac25af645ede262f9d6775579fdc"
        "3dbd8fb3a21e11776773ca011d06e223"
        "1884dbaa87119abb63945be6393ef598"
    );
    
    EXPECT_EQ(master_secret.size(), 48);
    EXPECT_EQ(master_secret, expected);
}

// Test TLS 1.2 PRF key expansion with SHA-256
TEST_F(KdfTest, Tls12PrfKeyExpansion) {
    auto client = Client::connect(TEST_SOCKET);
    
    // Use the master secret from the previous test
    auto master_secret = hex_to_bytes(
        "f999ac25af645ede262f9d6775579fdc"
        "3dbd8fb3a21e11776773ca011d06e223"
        "1884dbaa87119abb63945be6393ef598"
    );
    
    // For key expansion, seed = server_random + client_random (note: reversed order!)
    std::vector<uint8_t> server_random;
    for (uint8_t i = 0x20; i < 0x40; ++i) {
        server_random.push_back(i);
    }
    
    std::vector<uint8_t> client_random;
    for (uint8_t i = 0; i < 32; ++i) {
        client_random.push_back(i);
    }
    
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), server_random.begin(), server_random.end());
    seed.insert(seed.end(), client_random.begin(), client_random.end());
    
    // Create KDF params for key expansion (72 bytes for AES-128-CBC with SHA256)
    auto params = KdfParams::tls12_key_expansion(master_secret, seed, 72);
    
    auto key_block = client->derive_key(params);
    
    // Expected key block (computed using Python HMAC reference implementation)
    auto expected = hex_to_bytes(
        "f03e70e9289f53bf352f46640a8ff8ff"
        "de6e9ac4117b66a7262fa27f2b4dcf67"
        "d9ce32144bfbd8e4a583887e9bd79a08"
        "31a672310594bb276bd12035101a7f47"
        "516ae085dcef4ff4"
    );
    
    EXPECT_EQ(key_block.size(), 72);
    EXPECT_EQ(key_block, expected);
}

// Test TLS 1.2 PRF with SHA-384
TEST_F(KdfTest, Tls12EmsPrfSha384) {
    auto client = Client::connect(TEST_SOCKET);
    
    // Test with SHA-384 (used in TLS_*_SHA384 cipher suites)
    std::vector<uint8_t> secret(48, 0x0b);
    
    // Seed (note: this is passed as info in the API)
    std::vector<uint8_t> seed = {
        't', 'e', 's', 't', ' ', 'l', 'a', 'b', 'e', 'l',
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    
    KdfParams params{
        .algorithm = KdfAlgorithm::Tls12EmsPrfSha384,
        .ikm = secret,
        .output_len = 48,
        .salt = std::nullopt,
        .info = seed,
        .label = Tls12PrfLabel::ExtendedMasterSecret,
        .iterations = std::nullopt,
    };
    
    auto result = client->derive_key(params);
    
    // Expected output (computed using Python HMAC reference implementation with SHA-384)
    auto expected = hex_to_bytes(
        "94e5b8b366d6c35f4f0ceb82bfb5f31c"
        "126a2c5a6aa06ac63fa2aed72c418477"
        "0667a2279b5964e4b64520ab92f0c76c"
    );
    
    EXPECT_EQ(result.size(), 48);
    EXPECT_EQ(result, expected);
}

// Test convenience constructors
TEST_F(KdfTest, ConvenienceConstructors) {
    std::vector<uint8_t> secret(32, 0x42);
    std::vector<uint8_t> seed(64, 0x55);
    
    // Test tls12_master_secret
    auto params1 = KdfParams::tls12_master_secret(secret, seed);
    EXPECT_EQ(params1.algorithm, KdfAlgorithm::Tls12EmsPrfSha256);
    EXPECT_EQ(params1.output_len, 48);
    EXPECT_TRUE(params1.label.has_value());
    EXPECT_EQ(*params1.label, Tls12PrfLabel::MasterSecret);
    
    // Test tls12_master_secret with SHA-384
    auto params2 = KdfParams::tls12_master_secret(secret, seed, true);
    EXPECT_EQ(params2.algorithm, KdfAlgorithm::Tls12EmsPrfSha384);
    
    // Test tls12_key_expansion
    auto params3 = KdfParams::tls12_key_expansion(secret, seed, 72);
    EXPECT_EQ(params3.algorithm, KdfAlgorithm::Tls12EmsPrfSha256);
    EXPECT_EQ(params3.output_len, 72);
    EXPECT_TRUE(params3.label.has_value());
    EXPECT_EQ(*params3.label, Tls12PrfLabel::KeyExpansion);
}


} // namespace
} // namespace cryptod

#endif