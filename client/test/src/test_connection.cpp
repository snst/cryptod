// Connection tests

#include <gtest/gtest.h>
#include "cryptod/client.hpp"
#include "cryptod/error.hpp"

namespace cryptod {
namespace {

class ConnectionTest : public ::testing::Test {
protected:
    // Note: These tests require a running daemon
    // In CI, we would start the daemon before running tests
    
    static constexpr const char* TEST_SOCKET = "/tmp/cryptod.sock";
};

TEST_F(ConnectionTest, ConnectToNonexistentSocket) {
    EXPECT_THROW(
        Client::connect("/tmp/nonexistent_cryptod.sock"),
        CryptoException
    );
}

TEST_F(ConnectionTest, ConnectToRunningDaemon) {
    // This test requires a running daemon
    auto client = Client::connect(TEST_SOCKET);
    EXPECT_NE(client, nullptr);
}

} // namespace
} // namespace cryptod
