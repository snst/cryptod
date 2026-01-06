// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <gtest/gtest.h>
#include "keystore.h"

class KeyStoreTest : public testing::Test
{
protected:
  void SetUp() override
  {
  }
  const SecureVector masterKey;
  const SecureVector key1;
  const SecureVector key2;

  KeyStoreTest() : masterKey(32, 99), key1(32, 11), key2(32, 22) {}
};

TEST_F(KeyStoreTest, addKey)
{
  std::string keystoreFile = "testkeystore.dat";
  std::vector<AclEntry> uidAcl = {AclEntry{1000, static_cast<uint16_t>(KeyPermission::Hmac)}};

  KeyStore store1;
  store1.setMasterKey(masterKey);
  store1.addKey(1, KeyType::Symmetric, 256, key1, uidAcl);
  store1.addKey(2, KeyType::Symmetric, 256, key2, uidAcl);
  store1.saveStore(keystoreFile);

  KeyStore store2;
  store2.setMasterKey(masterKey);
  store2.loadStore(keystoreFile);

  EXPECT_FALSE(key1 == key2);

  auto rKey1 = store2.getKeyWithAccessCheck(1, 1000, 0, KeyPermission::Hmac);
  EXPECT_EQ(crypto_code_t::OK, rKey1.status);
  EXPECT_TRUE(key1 == rKey1.data);

  auto rKey2 = store2.getKeyWithAccessCheck(2, 1000, 0, KeyPermission::Hmac);
  EXPECT_EQ(crypto_code_t::OK, rKey2.status);
  EXPECT_TRUE(key2 == rKey2.data);

  auto rKey3 = store2.getKeyWithAccessCheck(3, 1000, 0, KeyPermission::Hmac);
  EXPECT_EQ(crypto_code_t::KEY_NOT_FOUND, rKey3.status);

  auto rKey2uid = store2.getKeyWithAccessCheck(2, 1001, 0, KeyPermission::Hmac);
  EXPECT_EQ(crypto_code_t::NO_ACCESS, rKey2uid.status);

  auto rKey2perm = store2.getKeyWithAccessCheck(2, 1000, 0, KeyPermission::Sign);
  EXPECT_EQ(crypto_code_t::NO_ACCESS, rKey2perm.status);

  EXPECT_FALSE(key1 == rKey2.data);
  EXPECT_FALSE(key2 == rKey1.data);
}
