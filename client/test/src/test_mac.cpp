// MAC tests

#include "cryptod/client.hpp"
#include "cryptod/key.hpp"
#include "cryptod/mac.hpp"
#include "test_utils.hpp"
#include <gtest/gtest.h>

namespace cryptod {
namespace {

using test::hex_to_bytes;

class MacTest : public ::testing::Test {
protected:
  static constexpr const char *TEST_SOCKET = "/tmp/cryptod.sock";
};

// RFC 4231 Test Case 2: HMAC-SHA256 with known key and expected output
TEST_F(MacTest, HmacSha256KnownVector) {
  auto client = Client::connect(TEST_SOCKET);

  // RFC 4231 Test Case 2
  // Key: "Jefe" (0x4a656665)
  // Data: "what do ya want for nothing?"
  // HMAC-SHA256:
  // 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843

  std::vector<uint8_t> key_material = {'J', 'e', 'f', 'e'};
  std::string message = "what do ya want for nothing?";
  std::vector<uint8_t> expected_hmac = hex_to_bytes(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  // Import the known key using factory method
  ImportKeyParams params("imported-key-test", KeyFormat::Raw, key_material,
                         KeyUsage::all(), true);
  auto key = client->import_key(params);

  // Compute HMAC
  auto ctx = client->mac(MacAlgorithm::HmacSha256, key);
  ctx->update(message);
  auto computed_hmac = ctx->finish();

  // Verify against expected value
  ASSERT_EQ(computed_hmac.size(), expected_hmac.size());
  EXPECT_EQ(computed_hmac, expected_hmac);

  client->delete_key(key);
}

TEST_F(MacTest, HmacSha256Basic) {
  auto client = Client::connect(TEST_SOCKET);

  CreateKeyParams params("hmac", SymmetricKeySize::Bits256, KeyUsage::all(),
                         true);

  // Create a symmetric key for HMAC
  auto key = client->create_key(params);

  auto ctx = client->mac(MacAlgorithm::HmacSha256, key);
  EXPECT_EQ(ctx->output_size(), 32);

  ctx->update("hello world");
  auto tag = ctx->finish();

  EXPECT_EQ(tag.size(), 32);

  // Cleanup
  client->delete_key(key);
}

TEST_F(MacTest, HmacSha256Verify) {
  auto client = Client::connect(TEST_SOCKET);

  CreateKeyParams params("hmac", SymmetricKeySize::Bits256, KeyUsage::all(),
                         true);

  auto key = client->create_key(params);

  // Compute MAC
  auto ctx1 = client->mac(MacAlgorithm::HmacSha256, key);
  ctx1->update("hello world");
  auto tag = ctx1->finish();

  // Verify MAC
  auto ctx2 = client->mac(MacAlgorithm::HmacSha256, key);
  ctx2->update("hello world");
  EXPECT_TRUE(ctx2->verify(tag));

  client->delete_key(key);
}

TEST_F(MacTest, HmacSha256VerifyFailure) {
  auto client = Client::connect(TEST_SOCKET);

  CreateKeyParams params("hmac", SymmetricKeySize::Bits256, KeyUsage::all(),
                         true);

  auto key = client->create_key(params);

  auto ctx = client->mac(MacAlgorithm::HmacSha256, key);
  ctx->update("hello world");

  // Wrong tag
  std::vector<uint8_t> wrong_tag(32, 0);
  EXPECT_FALSE(ctx->verify(wrong_tag));

  client->delete_key(key);
}

TEST_F(MacTest, HmacSha256Streaming) {
  auto client = Client::connect(TEST_SOCKET);

  CreateKeyParams params("hmac", SymmetricKeySize::Bits256, KeyUsage::all(),
                         true);
  auto key = client->create_key(params);

  auto ctx1 = client->mac(MacAlgorithm::HmacSha256, key);
  ctx1->update("hello ");
  ctx1->update("world");
  auto tag1 = ctx1->finish();

  auto ctx2 = client->mac(MacAlgorithm::HmacSha256, key);
  ctx2->update("hello world");
  auto tag2 = ctx2->finish();

  EXPECT_EQ(tag1, tag2);

  client->delete_key(key);
}

TEST_F(MacTest, HmacSha256KnownVectorParallel) {
  auto client = Client::connect(TEST_SOCKET);

  std::vector<uint8_t> key_material = {'J', 'e', 'f', 'e'};
  std::string message1 = "what do ya want";
  std::string message2 = " for nothing?";
  std::vector<uint8_t> expected_hmac = hex_to_bytes(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  // Import the known key using factory method
  ImportKeyParams params("imported-key-test", KeyFormat::Raw, key_material,
                         KeyUsage::all(), true);
  auto key = client->import_key(params);

  // Compute HMAC
  auto ctx1 = client->mac(MacAlgorithm::HmacSha256, key);
  auto ctx2 = client->mac(MacAlgorithm::HmacSha256, key);
  ctx1->update(message1);
  ctx2->update(message1);
  ctx1->update(message2);
  auto computed_hmac1 = ctx1->finish();

  ctx2->update(message2);
  auto computed_hmac2 = ctx2->finish();

  // Verify against expected value
  ASSERT_EQ(computed_hmac1.size(), expected_hmac.size());
  EXPECT_EQ(computed_hmac1, expected_hmac);

  ASSERT_EQ(computed_hmac2.size(), expected_hmac.size());
  EXPECT_EQ(computed_hmac2, expected_hmac);

  client->delete_key(key);
}

} // namespace
} // namespace cryptod
