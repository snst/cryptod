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

static double elapsed_sec(struct timespec start, struct timespec end)
{
    return (end.tv_sec - start.tv_sec) +
           (end.tv_nsec - start.tv_nsec) / 1e9;
}

int do_hmac(const char *provider, std::vector<uint8_t> &data, const void *key, size_t key_len, const char *digest, uint32_t n)
{
    printf("Provider:  %s\n", provider);

    /* Input data */
    unsigned char mac[EVP_MAX_MD_SIZE];
    size_t mac_len = 0;

    /* Load provider (default or fips) */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, provider);
    if (!prov)
    {
        fprintf(stderr, "Failed to load provider\n");
        return 1;
    }

    /* Fetch HMAC implementation */
    EVP_MAC *mac_algo = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac_algo)
    {
        fprintf(stderr, "Failed to fetch HMAC\n");
        return 1;
    }

    /* Create MAC context */
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac_algo);
    if (!ctx)
    {
        fprintf(stderr, "Failed to create MAC context\n");
        return 1;
    }

    /* Set HMAC parameters (digest = SHA256) */
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", (void *)digest, strlen(digest)),
        OSSL_PARAM_END};

    struct timespec t_start, t_end;

    clock_gettime(CLOCK_MONOTONIC, &t_start);

    for (uint32_t i = 0; i < n; i++)
    {
        /* Initialize */
        if (!EVP_MAC_init(ctx, (const uint8_t *)key, key_len, params))
        {
            fprintf(stderr, "EVP_MAC_init failed\n");
            return 1;
        }

        /* Process data */
        if (!EVP_MAC_update(ctx, data.data(), data.size()))
        {
            fprintf(stderr, "EVP_MAC_update failed\n");
            return 1;
        }

        /* Finalize */
        if (!EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac)))
        {
            fprintf(stderr, "EVP_MAC_final failed\n");
            return 1;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);

    double seconds = elapsed_sec(t_start, t_end);
    double total_bytes = (double)data.size() * n;
    double mbps = (total_bytes / (1024.0 * 1024.0)) / seconds;

    printf("Processed: %.2f MB\n", total_bytes / (1024.0 * 1024.0));
    printf("Time:      %.3f seconds\n", seconds);
    printf("Throughput %.2f MB/s\n", mbps);

    /* Print result */
    dumpHex(std::string("HMAC-") + std::string(digest), mac, mac_len);
    printf("\n\n");

    /* Cleanup */
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_algo);
    OSSL_PROVIDER_unload(prov);
    return 0;
}

int main(int argc, char *argv[])
{
    std::vector<uint8_t> input(1000);
    auto key = load_file("aes256_2.key");
    crypto_key_id_t key_id = 0xaa;

    uint32_t n = 100;

    do_hmac("libcryptod_provider", input, &key_id, sizeof(key_id), "SHA512", n);
    do_hmac("default", input, key.data(), key.size(), "SHA512", n);
    return 0;
}
