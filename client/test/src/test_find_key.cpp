// FindKey tests

#include "cryptod/client.hpp"
#include "cryptod/error.hpp"
#include "cryptod/key.hpp"
#include <gtest/gtest.h>

namespace cryptod {
namespace {

class FindKeyTest : public ::testing::Test {
protected:
  static constexpr const char *TEST_SOCKET = "/tmp/cryptod.sock";
};

TEST_F(FindKeyTest, FindKeyByLabel) {
  auto client = Client::connect(TEST_SOCKET);

  // Create a key with a specific label
  CreateKeyParams params("test-find-key-label", SymmetricKeySize::Bits256,
                         KeyUsage::all(), true);
  auto created_key = client->create_key(params);

  // Find the key by label
  auto query = FindKeyQuery::by_label("test-find-key-label");
  auto found = client->find_key(query);

  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(found->id(), created_key.id());

  // Cleanup
  client->delete_key(created_key);
}

TEST_F(FindKeyTest, FindKeyByLabelNotFound) {
  auto client = Client::connect(TEST_SOCKET);

  // Search for a label that doesn't exist
  auto query = FindKeyQuery::by_label("nonexistent-key-label-12345");
  auto found = client->find_key(query);

  EXPECT_FALSE(found.has_value());
}

TEST_F(FindKeyTest, FindKeyByLabelAfterDelete) {
  auto client = Client::connect(TEST_SOCKET);

  // Create a key with a specific label
  CreateKeyParams params("test-find-delete-label", SymmetricKeySize::Bits256,
                         KeyUsage::all(), true);
  auto key = client->create_key(params);

  // Verify key can be found
  auto query = FindKeyQuery::by_label("test-find-delete-label");
  auto found = client->find_key(query);
  ASSERT_TRUE(found.has_value());

  // Delete the key
  client->delete_key(key);

  // Verify key can no longer be found
  found = client->find_key(query);
  EXPECT_FALSE(found.has_value());
}

// --------------------------------------------------------
// Key Handle Tests
// --------------------------------------------------------

class KeyHandleTest : public ::testing::Test {
protected:
  static constexpr const char *TEST_SOCKET = "/tmp/cryptod.sock";
};

TEST_F(KeyHandleTest, KeyHandleIsNumeric) {
  auto client = Client::connect(TEST_SOCKET);

  // Create a key with a label
  CreateKeyParams params("numeric-id-test", SymmetricKeySize::Bits256,
                         KeyUsage::all(), true);
  auto key = client->create_key(params);

  // The returned handle should have a valid numeric ID
  EXPECT_GT(key.id(), 0u);

  // Cleanup
  client->delete_key(key);
}

TEST_F(KeyHandleTest, MultipleKeysHaveUniqueIds) {
  auto client = Client::connect(TEST_SOCKET);

  CreateKeyParams params1("key1", SymmetricKeySize::Bits256, KeyUsage::all(),
                          true);
  CreateKeyParams params2("key2", SymmetricKeySize::Bits256, KeyUsage::all(),
                          true);
  CreateKeyParams params3("key3", SymmetricKeySize::Bits256, KeyUsage::all(),
                          true);

  // Create multiple keys
  auto key1 = client->create_key(params1);
  auto key2 = client->create_key(params2);
  auto key3 = client->create_key(params3);

  // All should have unique numeric IDs
  EXPECT_NE(key1.id(), key2.id());
  EXPECT_NE(key2.id(), key3.id());
  EXPECT_NE(key1.id(), key3.id());

  // Cleanup
  client->delete_key(key1);
  client->delete_key(key2);
  client->delete_key(key3);
}

TEST_F(KeyHandleTest, KeyInfoContainsLabel) {
  auto client = Client::connect(TEST_SOCKET);

  // Create a key with a label
  CreateKeyParams params("info-label-test", SymmetricKeySize::Bits256,
                         KeyUsage::all(), true);

  auto key = client->create_key(params);

  // Get key info and verify label
  auto info = client->get_key_info(key);
  ASSERT_TRUE(info.label.has_value());
  EXPECT_EQ(*info.label, "info-label-test");

  // Cleanup
  client->delete_key(key);
}

TEST_F(KeyHandleTest, KeyUsableViaNumeridHandleForHmac) {
  auto client = Client::connect(TEST_SOCKET);

  // Create a key with a label
  CreateKeyParams params("hmac-handle-test", SymmetricKeySize::Bits256,
                         KeyUsage::all(), true);

  auto key = client->create_key(params);

  // Use the key via its numeric handle for HMAC
  auto ctx = client->mac(MacAlgorithm::HmacSha256, key);
  ctx->update("test data");
  auto mac = ctx->finish();

  // Verify we got a valid MAC
  EXPECT_EQ(mac.size(), 32u);

  // Cleanup
  client->delete_key(key);
}

TEST_F(KeyHandleTest, ImportedKeyHasNumericHandle) {
  auto client = Client::connect(TEST_SOCKET);

  // Import a key with a label
  std::vector<uint8_t> material = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

  ImportKeyParams params("imported-key-test", 
                         KeyFormat::Raw, material, KeyUsage::all(), true);
  auto key = client->import_key(params);

  // The handle should have a valid numeric ID
  EXPECT_GT(key.id(), 0u);

  // Find the key by label
  auto query = FindKeyQuery::by_label("imported-key-test");
  auto found = client->find_key(query);
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(found->id(), key.id());

  // Cleanup
  client->delete_key(key);
}

} // namespace
} // namespace cryptod
