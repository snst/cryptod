// Cipher tests

#include "cryptod/cipher.hpp"
#include "cryptod/client.hpp"
#include "cryptod/key.hpp"
#include "test_utils.hpp"
#include <gtest/gtest.h>

#include <algorithm>
#include <random>

namespace cryptod {
namespace {

using test::hex_to_bytes;

class CipherTest : public ::testing::Test {
protected:
  static constexpr const char *TEST_SOCKET = "/tmp/cryptod.sock";

  // Generate random bytes for testing
  static std::vector<uint8_t> random_bytes(size_t len) {
    std::vector<uint8_t> result(len);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::generate(result.begin(), result.end(), [&]() { return dis(gen); });
    return result;
  }
};

// NIST SP 800-38A AES-256-CBC Test Vector
TEST_F(CipherTest, Aes256CbcKnownVector) {
  auto client = Client::connect(TEST_SOCKET);

  // NIST AES-256-CBC test vector
  auto key_material = hex_to_bytes(
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
  auto iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
  auto plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
  auto expected_ciphertext = hex_to_bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6");

  // Import the known key using factory method (symmetric256 for versatile
  // usage)
  // auto params = ImportKeyParams::symmetric256(key_material);
  // params.extractable = true;
  ImportKeyParams params("key1", KeyFormat::Raw,
                         key_material, KeyUsage::all(), true);
  auto key = client->import_key(params);

  // Encrypt
  auto enc_ctx = client->cipher_encrypt(CipherParams::aes_cbc(iv), key);
  auto ciphertext = enc_ctx->update(plaintext);
  auto final_enc = enc_ctx->finish();
  ciphertext.insert(ciphertext.end(), final_enc.begin(), final_enc.end());

  // NIST test vector expects no padding for exact block size
  // Our implementation uses PKCS7 padding, so we get ciphertext + padding block
  // The first block should match the expected ciphertext
  ASSERT_GE(ciphertext.size(), expected_ciphertext.size());
  std::vector<uint8_t> first_block(ciphertext.begin(), ciphertext.begin() + 16);
  EXPECT_EQ(first_block, expected_ciphertext);

  // Decrypt and verify we get back the original plaintext
  auto dec_ctx = client->cipher_decrypt(CipherParams::aes_cbc(iv), key);
  auto decrypted = dec_ctx->update(ciphertext);
  auto final_dec = dec_ctx->finish();
  decrypted.insert(decrypted.end(), final_dec.begin(), final_dec.end());

  EXPECT_EQ(decrypted, plaintext);

  client->delete_key(key);
}

TEST_F(CipherTest, AesCbcRoundtrip) {
  auto client = Client::connect(TEST_SOCKET);

  CreateKeyParams params("aescbc", SymmetricKeySize::Bits256, KeyUsage::all(),
                         true);

  auto key = client->create_key(params);
  auto iv = random_bytes(16);
  auto plaintext = random_bytes(64);

  // Encrypt
  auto enc_ctx = client->cipher_encrypt(CipherParams::aes_cbc(iv), key);
  auto ciphertext = enc_ctx->update(plaintext);
  auto final_enc = enc_ctx->finish();
  ciphertext.insert(ciphertext.end(), final_enc.begin(), final_enc.end());

  // Decrypt
  auto dec_ctx = client->cipher_decrypt(CipherParams::aes_cbc(iv), key);
  auto decrypted = dec_ctx->update(ciphertext);
  auto final_dec = dec_ctx->finish();
  decrypted.insert(decrypted.end(), final_dec.begin(), final_dec.end());

  EXPECT_EQ(plaintext, decrypted);

  client->delete_key(key);
}

// TEST_F(CipherTest, DISABLED_AesGcmRoundtrip) {
//   auto client = Client::connect(TEST_SOCKET);

//   auto key = client->create_key(CreateKeyParams::symmetric256());
//   auto nonce = random_bytes(12);
//   auto plaintext = random_bytes(64);
//   auto aad = random_bytes(16);

//   // Encrypt
//   auto enc_ctx =
//       client->cipher_encrypt(CipherParams::aes_gcm_with_aad(nonce, aad),
//       key);
//   auto ciphertext = enc_ctx->update(plaintext);
//   auto final_enc = enc_ctx->finish();
//   ciphertext.insert(ciphertext.end(), final_enc.begin(), final_enc.end());
//   auto tag = enc_ctx->get_tag();
//   ASSERT_TRUE(tag.has_value());

//   // Decrypt
//   auto dec_ctx =
//       client->cipher_decrypt(CipherParams::aes_gcm_with_aad(nonce, aad),
//       key);
//   dec_ctx->set_tag(*tag);
//   auto decrypted = dec_ctx->update(ciphertext);
//   auto final_dec = dec_ctx->finish();
//   decrypted.insert(decrypted.end(), final_dec.begin(), final_dec.end());

//   EXPECT_EQ(plaintext, decrypted);

//   client->delete_key(key);
// }

// TEST_F(CipherTest, DISABLED_AesGcmAuthenticationFailure) {
//   auto client = Client::connect(TEST_SOCKET);

//   auto key = client->create_key(CreateKeyParams::symmetric256());
//   auto nonce = random_bytes(12);
//   auto plaintext = random_bytes(64);

//   // Encrypt
//   auto enc_ctx = client->cipher_encrypt(CipherParams::aes_gcm(nonce), key);
//   auto ciphertext = enc_ctx->update(plaintext);
//   enc_ctx->finish();

//   // Tamper with ciphertext
//   if (!ciphertext.empty()) {
//     ciphertext[0] ^= 0xFF;
//   }

//   // Decrypt should fail
//   auto dec_ctx = client->cipher_decrypt(CipherParams::aes_gcm(nonce), key);
//   dec_ctx->update(ciphertext);

//   EXPECT_THROW(dec_ctx->finish(), CryptoException);

//   client->delete_key(key);
// }

} // namespace
} // namespace cryptod
