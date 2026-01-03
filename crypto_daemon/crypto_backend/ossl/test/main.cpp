// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <gtest/gtest.h>
#include "ossl_backend.h"
#include "helpers.h"

class OsslBackendTest : public testing::Test
{
protected:
    void SetUp() override
    {
    }

    OsslBackendTest() {}
    OpenSSLBackend backend;
};

TEST_F(OsslBackendTest, hmac)
{
    SecureVector hmac_key = {0x01, 0x02, 0x03, 0x04};
    auto hmac = backend.createHMAC(HASH_ALG_SHA256, hmac_key);
    hmac->init();
    hmac->update((uint8_t *)"Hello", 5);
    hmac->update((uint8_t *)"World", 5);
    auto hmac_result = hmac->finish();

    std::string expected_hex = "b748993a13f79584f355a53a955190757fd5a978766c46c548a5deac8507e596";
    auto expected_vec = stringToVector(expected_hex);

    EXPECT_EQ(expected_vec, hmac_result.vector());
}

bool ecdsa_verify(OpenSSLBackend &backend, std::vector<uint8_t> input, std::vector<uint8_t> pub_key, std::vector<uint8_t> signature)
{
    auto ecdsa_verify = backend.createECDSA("P-256", false, pub_key);
    ecdsa_verify->init();
    ecdsa_verify->update(input.data(), input.size());
    bool ret = ecdsa_verify->verify(signature.data(), signature.size());
    return ret;
}

TEST_F(OsslBackendTest, ecdsa)
{
    auto priv_key = load_file("../data/ec_private.der");
    auto pub_key = load_file("../data/ec_public.der");
    auto input1 = load_file("../data/input1.txt");
    auto input2 = load_file("../data/input2.txt");
    auto signature1_ext = load_file("../data/signature.der");

    EXPECT_TRUE(priv_key.size() > 0);
    EXPECT_TRUE(pub_key.size() > 0);
    EXPECT_TRUE(input1.size() > 0);
    EXPECT_TRUE(input2.size() > 0);
    EXPECT_TRUE(signature1_ext.size() > 0);

    auto ecdsa_sign = backend.createECDSA("P-256", true, priv_key);
    ecdsa_sign->init();
    ecdsa_sign->update(input1.data(), input1.size());
    auto signature1 = ecdsa_sign->finish();

    EXPECT_TRUE(ecdsa_verify(backend, input1, pub_key, signature1_ext));
    EXPECT_TRUE(ecdsa_verify(backend, input1, pub_key, signature1.vector()));
    EXPECT_FALSE(ecdsa_verify(backend, input2, pub_key, signature1_ext));
}
