// MAC tests

#include "cryptod/client.hpp"
#include "cryptod/key.hpp"
#include "cryptod/mac.hpp"
#include "test_utils.hpp"
#include <gtest/gtest.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/store.h>

namespace cryptod {
namespace {

using test::hex_to_bytes;
static constexpr const char *TEST_SOCKET = "/tmp/cryptod.sock";

class OsslMacTest : public ::testing::Test {
protected:
  std::shared_ptr<Client> client;
  std::string keylabel_ = "key123";
  std::vector<uint8_t> key_material_ = {'J', 'e', 'f', 'e'};
  std::vector<uint8_t> expected_hmac_;
  const char *cryptod_provider_ = "libcryptod_provider";
  const char *default_provider_ = "default";
  const char *digest_ = "SHA256";
  std::string message_ = "what do ya want for nothing?";

  void SetUp() override {
    client = Client::connect(TEST_SOCKET);
    // Import the known key using factory method
    ImportKeyParams params(keylabel_, KeyFormat::Raw, key_material_,
                           KeyUsage::all(), true);
    client->import_key(params);
    expected_hmac_ = hex_to_bytes(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  }

  void TearDown() override {
    // Cleanup code after test
    auto query = FindKeyQuery::by_label(keylabel_);
    auto key = client->find_key(query);
    if (key.has_value()) {
      client->delete_key(key.value());
    }
  }
};

// RFC 4231 Test Case 2: HMAC-SHA256 with known key and expected output
TEST_F(OsslMacTest, HmacSha256KnownVector) {

  OSSL_LIB_CTX *lib_ctx = NULL;
  OSSL_PROVIDER *default_prov = NULL;
  OSSL_PROVIDER *prov = NULL;
  EVP_MAC *mac_algo = NULL;
  EVP_MAC_CTX *ctx = NULL;
  // OSSL_STORE_CTX *store = NULL;
  // OSSL_STORE_INFO *store_info = NULL;
  // std::string key_uri = "cryptod:" + keylabel;
  // EVP_PKEY *pkey = NULL;

  unsigned char mac[EVP_MAX_MD_SIZE];
  size_t mac_len = 0;
  lib_ctx = OSSL_LIB_CTX_new();
  ASSERT_TRUE(lib_ctx != NULL);

  // default_prov = OSSL_PROVIDER_load(lib_ctx, default_provider_);
  // ASSERT_TRUE(default_prov != NULL);

  prov = OSSL_PROVIDER_load(lib_ctx, cryptod_provider_);
  ASSERT_TRUE(prov != NULL);

  // store = OSSL_STORE_open_ex(key_uri.c_str(), lib_ctx, NULL, NULL, NULL,
  // NULL,
  //                            NULL, NULL);
  // ASSERT_TRUE(store != NULL);

  // store_info = OSSL_STORE_load(store);
  // ASSERT_TRUE(store_info != NULL);
  // ASSERT_EQ(OSSL_STORE_INFO_get_type(store_info), OSSL_STORE_INFO_PKEY);

  // pkey = OSSL_STORE_INFO_get1_PKEY(store_info);
  // ASSERT_TRUE(pkey != NULL);

  mac_algo = EVP_MAC_fetch(lib_ctx, "HMAC", NULL);
  ASSERT_TRUE(mac_algo != NULL);

  ctx = EVP_MAC_CTX_new(mac_algo);
  ASSERT_TRUE(ctx != NULL);

  OSSL_PARAM params[] = {
      OSSL_PARAM_utf8_string("digest", (void *)digest_, strlen(digest_)),
      OSSL_PARAM_utf8_string("key_label", (void *)keylabel_.c_str(),
                             keylabel_.length()),
      //        OSSL_PARAM_construct_octet_ptr("key_label2", (void **)&pkey,
      //        sizeof(pkey)),
      OSSL_PARAM_END};

  ASSERT_NE(0, EVP_MAC_init(ctx, (const unsigned char *)NULL, 0, params));
  ASSERT_NE(0, EVP_MAC_update(ctx, (const unsigned char *)message_.c_str(),
                              message_.length()));
  ASSERT_NE(0, EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac)));

  ASSERT_EQ(mac_len, expected_hmac_.size());
  auto computed_hmac = std::vector<uint8_t>(mac, mac + mac_len);
  EXPECT_EQ(computed_hmac, expected_hmac_);

  if (ctx)
    EVP_MAC_CTX_free(ctx);

  if (mac_algo)
    EVP_MAC_free(mac_algo);

  // if (pkey)
  //     EVP_PKEY_free(pkey);

  // if (store_info)
  //     OSSL_STORE_INFO_free(store_info);

  // if (store)
  //     OSSL_STORE_close(store);

  if (prov)
    OSSL_PROVIDER_unload(prov);

  // if (default_prov)
  //     OSSL_PROVIDER_unload(default_prov);

  if (lib_ctx)
    OSSL_LIB_CTX_free(lib_ctx);
}

TEST_F(OsslMacTest, HmacSha256KnownVectorPlainKey) {

  OSSL_LIB_CTX *lib_ctx = NULL;
  OSSL_PROVIDER *default_prov = NULL;
  OSSL_PROVIDER *prov = NULL;
  EVP_MAC *mac_algo = NULL;
  EVP_MAC_CTX *ctx = NULL;

  unsigned char mac[EVP_MAX_MD_SIZE];
  size_t mac_len = 0;
  lib_ctx = OSSL_LIB_CTX_new();
  ASSERT_TRUE(lib_ctx != NULL);

  // default_prov = OSSL_PROVIDER_load(lib_ctx, default_provider_);
  // ASSERT_TRUE(default_prov != NULL);

  prov = OSSL_PROVIDER_load(lib_ctx, cryptod_provider_);
  ASSERT_TRUE(prov != NULL);

  mac_algo = EVP_MAC_fetch(lib_ctx, "HMAC", NULL);
  ASSERT_TRUE(mac_algo != NULL);

  ctx = EVP_MAC_CTX_new(mac_algo);
  ASSERT_TRUE(ctx != NULL);

  OSSL_PARAM params[] = {
      OSSL_PARAM_utf8_string("digest", (void *)digest_, strlen(digest_)),
      OSSL_PARAM_END};

  ASSERT_NE(0, EVP_MAC_init(ctx, (const uint8_t *)key_material_.data(),
                            key_material_.size(), params));

  ASSERT_NE(0, EVP_MAC_update(ctx, (const unsigned char *)message_.c_str(),
                              message_.length()));

  ASSERT_NE(0, EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac)));

  ASSERT_EQ(mac_len, expected_hmac_.size());
  auto computed_hmac = std::vector<uint8_t>(mac, mac + mac_len);
  EXPECT_EQ(computed_hmac, expected_hmac_);

  if (ctx)
    EVP_MAC_CTX_free(ctx);

  if (mac_algo)
    EVP_MAC_free(mac_algo);

  if (prov)
    OSSL_PROVIDER_unload(prov);

  if (default_prov)
    OSSL_PROVIDER_unload(default_prov);

  if (lib_ctx)
    OSSL_LIB_CTX_free(lib_ctx);
}

TEST(Ossl, AddKey) {
  std::string keylabel_ = "key123";
  std::vector<uint8_t> key_material_ = {'J', 'e', 'f', 'e'};

  auto client = Client::connect(TEST_SOCKET);
  // Import the known key using factory method
  ImportKeyParams params(keylabel_, KeyFormat::Raw, key_material_,
                         KeyUsage::all(), true);
  client->import_key(params);
}

TEST(Ossl, DelKey) {
  std::string keylabel_ = "key123";

  auto client = Client::connect(TEST_SOCKET);
  auto query = FindKeyQuery::by_label(keylabel_);
  auto key = client->find_key(query);
  if (key.has_value()) {
    client->delete_key(key.value());
  }
}

TEST(Ossl, AddTlsKey) {
  std::string keylabel_ = "ABCD";
  std::vector<uint8_t> key_material_ = hex_to_bytes("aabbccddeeff");

  auto client = Client::connect(TEST_SOCKET);

  auto query = FindKeyQuery::by_label(keylabel_);
  auto key = client->find_key(query);
  if (key.has_value()) {
    client->delete_key(key.value());
  }

  // Import the known key using factory method
  ImportKeyParams params(keylabel_, KeyFormat::Raw, key_material_,
                         KeyUsage::all(), true);
  client->import_key(params);
}

TEST(Ossl, AddWrongTlsKey) {
  std::string keylabel_ = "ABCD";
  std::vector<uint8_t> key_material_ = hex_to_bytes("aabbccddeeaa");

  auto client = Client::connect(TEST_SOCKET);

  auto query = FindKeyQuery::by_label(keylabel_);
  auto key = client->find_key(query);
  if (key.has_value()) {
    client->delete_key(key.value());
  }

  // Import the known key using factory method
  ImportKeyParams params(keylabel_, KeyFormat::Raw, key_material_,
                         KeyUsage::all(), true);
  client->import_key(params);
}

TEST(Ossl, DelTlsKey) {
  std::string keylabel_ = "ABCD";

  auto client = Client::connect(TEST_SOCKET);
  auto query = FindKeyQuery::by_label(keylabel_);
  auto key = client->find_key(query);
  if (key.has_value()) {
    client->delete_key(key.value());
  }
}

} // namespace
} // namespace cryptod