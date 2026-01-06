// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include "helpers.h"
#include "crypto_types.h"
#include "crypto_exception.h"
#include "log_macro.h"

static double elapsed_sec(struct timespec start, struct timespec end)
{
    return (end.tv_sec - start.tv_sec) +
           (end.tv_nsec - start.tv_nsec) / 1e9;
}

int do_hmac(const char *provider, std::vector<uint8_t> &data, const void *key, size_t key_len, const char *digest, uint32_t n)
{
    LOG_INFO("Provider:  %s", provider);
    OSSL_LIB_CTX *lib_ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    EVP_MAC *mac_algo = NULL;
    EVP_MAC_CTX *ctx = NULL;
    try
    {
        unsigned char mac[EVP_MAX_MD_SIZE];
        size_t mac_len = 0;
        lib_ctx = OSSL_LIB_CTX_new();
        if (!lib_ctx)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "OSSL_LIB_CTX_new"));

        prov = OSSL_PROVIDER_load(lib_ctx, provider);
        if (!prov)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "Failed to load provider"));

        mac_algo = EVP_MAC_fetch(lib_ctx, "HMAC", NULL);
        if (!mac_algo)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "Failed to fetch HMAC"));

        ctx = EVP_MAC_CTX_new(mac_algo);
        if (!ctx)
            throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "Failed to create MAC context"));

        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string("digest", (void *)digest, strlen(digest)),
            OSSL_PARAM_END};

        struct timespec t_start, t_end;

        clock_gettime(CLOCK_MONOTONIC, &t_start);

        for (uint32_t i = 0; i < n; i++)
        {
            if (!EVP_MAC_init(ctx, (const uint8_t *)key, key_len, params))
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "EVP_MAC_init failed"));

            if (!EVP_MAC_update(ctx, data.data(), data.size()))
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "EVP_MAC_update failed"));

            if (!EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac)))
                throw(CryptoException(crypto_code_t::CRYPTO_ERROR, "EVP_MAC_final failed"));
        }

        clock_gettime(CLOCK_MONOTONIC, &t_end);

        double seconds = elapsed_sec(t_start, t_end);
        double total_bytes = (double)data.size() * n;
        double mbps = (total_bytes / (1024.0 * 1024.0)) / seconds;

        LOG_INFO("Processed: %.2f MB", total_bytes / (1024.0 * 1024.0));
        LOG_INFO("Time:      %.3f seconds", seconds);
        LOG_INFO("Throughput %.2f MB/s", mbps);

        /* Print result */
        dumpHex(std::string("HMAC-") + std::string(digest), mac, mac_len);
        LOG_INFO("\n\n");
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
    }

    if (ctx)
        EVP_MAC_CTX_free(ctx);

    if (mac_algo)
        EVP_MAC_free(mac_algo);

    if (prov)
        OSSL_PROVIDER_unload(prov);

    if (lib_ctx)
        OSSL_LIB_CTX_free(lib_ctx);

    return 0;
}

int main(int argc, char *argv[])
{
    std::vector<uint8_t> input(512);
    auto key = load_file("aes256_2.key");
    crypto_key_id_t key_id = 0xaa;

    uint32_t n = 200000;

    do_hmac("libcryptod_provider", input, &key_id, sizeof(key_id), "SHA512", n);
    do_hmac("default", input, key.data(), key.size(), "SHA512", n);
    return 0;
}
