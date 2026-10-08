// Hash tests

#include <gtest/gtest.h>
#include "cryptod/client.hpp"
#include "cryptod/hash.hpp"
#include "test_utils.hpp"

namespace cryptod {
namespace {

using test::hex_to_bytes;

class HashTest : public ::testing::Test {
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

// Known SHA-256 test vectors
TEST_F(HashTest, Sha256KnownVectors) {
    auto client = Client::connect(TEST_SOCKET);
    
    // SHA-256("abc") - NIST test vector
    {
        auto ctx = client->hash(HashAlgorithm::Sha256);
        ctx->update("abc");
        auto digest = ctx->finish();
        
        auto expected = hex_to_bytes(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        EXPECT_EQ(digest, expected);
    }
    
    // SHA-256("hello world")
    {
        auto ctx = client->hash(HashAlgorithm::Sha256);
        ctx->update("hello world");
        auto digest = ctx->finish();
        
        auto expected = hex_to_bytes(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        EXPECT_EQ(digest, expected);
    }
    
    // SHA-256("") - empty string
    {
        auto ctx = client->hash(HashAlgorithm::Sha256);
        auto digest = ctx->finish();
        
        auto expected = hex_to_bytes(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        EXPECT_EQ(digest, expected);
    }
}

TEST_F(HashTest, SHA256Basic) {
    // Requires running daemon
    auto client = Client::connect(TEST_SOCKET);
    
    auto ctx = client->hash(HashAlgorithm::Sha256);
    EXPECT_EQ(ctx->output_size(), 32);
    
    ctx->update("hello world");
    auto digest = ctx->finish();
    
    EXPECT_EQ(digest.size(), 32);
}

TEST_F(HashTest, SHA256Streaming) {
    auto client = Client::connect(TEST_SOCKET);
    
    auto ctx1 = client->hash(HashAlgorithm::Sha256);
    ctx1->update("hello ");
    ctx1->update("world");
    auto digest1 = ctx1->finish();
    
    auto ctx2 = client->hash(HashAlgorithm::Sha256);
    ctx2->update("hello world");
    auto digest2 = ctx2->finish();
    
    EXPECT_EQ(digest1, digest2);
}

TEST_F(HashTest, SHA384Basic) {
    auto client = Client::connect(TEST_SOCKET);
    
    auto ctx = client->hash(HashAlgorithm::Sha384);
    EXPECT_EQ(ctx->output_size(), 48);
    
    ctx->update("test");
    auto digest = ctx->finish();
    
    EXPECT_EQ(digest.size(), 48);
}

TEST_F(HashTest, EmptyInput) {
    auto client = Client::connect(TEST_SOCKET);
    
    auto ctx = client->hash(HashAlgorithm::Sha256);
    // No update calls
    auto digest = ctx->finish();
    
    // SHA-256 of empty string
    EXPECT_EQ(digest.size(), 32);
}

} // namespace
} // namespace cryptod
