// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include "helpers.h"
#include "crypto_types.h"
#include "crypto_exception.h"
#include "log_macro.h"
#include <gtest/gtest.h>

static double elapsed_sec(struct timespec start, struct timespec end)
{
    return (end.tv_sec - start.tv_sec) +
           (end.tv_nsec - start.tv_nsec) / 1e9;
}

class HMac
{
public:
    HMac(const char *provider)
    {
        lib_ctx_ = OSSL_LIB_CTX_new();
        if (!lib_ctx_)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "OSSL_LIB_CTX_new"));

        prov_ = OSSL_PROVIDER_load(lib_ctx_, provider);
        if (!prov_)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "Failed to load provider"));

        mac_algo_ = EVP_MAC_fetch(lib_ctx_, "HMAC", NULL);
        if (!mac_algo_)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "Failed to fetch HMAC"));
    }

    ~HMac()
    {
        if (mac_algo_)
            EVP_MAC_free(mac_algo_);

        if (prov_)
            OSSL_PROVIDER_unload(prov_);

        if (lib_ctx_)
            OSSL_LIB_CTX_free(lib_ctx_);
    }

    std::vector<uint8_t> calc(std::vector<uint8_t> &data, const void *key, size_t key_len, const char *digest)
    {
        EVP_MAC_CTX *ctx = NULL;
        size_t mac_out_len = 0;
        std::vector<uint8_t> hmac(EVP_MAX_MD_SIZE);

        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string("digest", (void *)digest, strlen(digest)),
            OSSL_PARAM_END};

        try
        {
            ctx = EVP_MAC_CTX_new(mac_algo_);
            if (!ctx)
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "Failed to create MAC context"));

            if (!EVP_MAC_init(ctx, (const uint8_t *)key, key_len, params))
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "EVP_MAC_init failed"));

            if (!EVP_MAC_update(ctx, data.data(), data.size()))
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "EVP_MAC_update failed"));

            if (!EVP_MAC_final(ctx, hmac.data(), &mac_out_len, hmac.size()))
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "EVP_MAC_final failed"));
            hmac.resize(mac_out_len);
        }
        catch (const CryptoException &e)
        {
            hmac.resize(0);
            LOG_EXCEPTION(e.what());
        }

        if (ctx)
            EVP_MAC_CTX_free(ctx);

        return hmac;
    }

    OSSL_PROVIDER *prov_ = NULL;
    OSSL_LIB_CTX *lib_ctx_ = NULL;
    EVP_MAC *mac_algo_ = NULL;
};

class MTTest
{
protected:
    std::vector<std::thread> threads_;
    std::atomic<bool> running_;
    uint32_t id_;
    std::vector<uint8_t> key1_;
    std::vector<uint8_t> key2_;
    HMac provHmac_;
    const char *sha_;
    size_t input_len_;
    std::atomic<size_t> processed_len_{0};
    std::atomic<size_t> processed_calls_{0};

public:
    MTTest(const char *sha = NULL, size_t input_len = 0)
        : provHmac_("libcryptod_provider"), sha_(sha), input_len_(input_len)
    {
        key1_ = load_file("aes256_1.key");
        key2_ = load_file("aes256_2.key");
    }

    const char *randomHashAlg()
    {
        // Array of hash names (static so pointers remain valid)
        static const char *hashes[] = {
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512"};
        static const size_t num_hashes = sizeof(hashes) / sizeof(hashes[0]);

        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<size_t> dist(0, num_hashes - 1);
        return hashes[dist(rng)];
    }

    void work()
    {
        while (running_)
        {
            crypto_key_id_t kid = 0x11;
            const char *sha = sha_ ? sha_ : randomHashAlg();
            std::vector<uint8_t> input(input_len_ ? input_len_ : std::rand() % 2056);
            std::generate(input.begin(), input.end(), std::rand);
            HMac defHmac("default");
            auto defOut = defHmac.calc(input, key1_.data(), key1_.size(), sha);
            auto provOut = provHmac_.calc(input, &kid, sizeof(kid), sha);
            EXPECT_EQ(defOut, provOut);
            size_t n = processed_calls_.fetch_add(1, std::memory_order_relaxed);
            processed_len_.fetch_add(input.size(), std::memory_order_relaxed);
            bool ok = defOut == provOut;
            // LOG_INFO("t %u, n=%lu, %s, len=%lu", id, processed_calls.load(std::memory_order_relaxed), sha, input.size());
            // LOG_INFO("t %u, n=%lu, %s, len=%lu", id, n, sha, input.size());
        }
    }

    void run(uint32_t n)
    {
        id_ = 0;
        running_ = true;
        for (uint32_t i = 0; i < n; i++)
        {
            threads_.push_back(std::thread(&MTTest::work, this));
        }
    }

    void stop()
    {
        running_ = false;
        while (!threads_.empty())
        {
            auto &t = threads_.at(0);
            if (t.joinable())
            {
                t.join();
            }
            threads_.erase(threads_.begin());
        }
        LOG_INFO("Processed %lu calls. %lu kb data", processed_calls_.load(std::memory_order_relaxed),
                 processed_len_.load(std::memory_order_relaxed) / 1024);
    }
};

TEST(TestConcurrent, HMAC)
{
    std::vector<uint8_t> input(512);
    auto key2 = load_file("aes256_2.key");
    crypto_key_id_t key_id2 = 0x22;

    MTTest t("SHA256", 1024);
    t.run(10);
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    t.stop();
}
