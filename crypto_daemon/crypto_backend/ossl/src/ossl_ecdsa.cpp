// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "ossl_backend.h"
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "crypto_exception.h"

#define ENABLE_LOGGING
#include "log_macro.h"

OsslEcdsa::OsslEcdsa(const std::string &curve, bool sign_mode,
                     const SecureVector &key_data)
    : pkey_(nullptr), mdctx_(nullptr), sign_mode_(sign_mode), initialized_(false)
{

    int nid = NID_undef;
    if (curve == "P-256")
        nid = NID_X9_62_prime256v1;
    else if (curve == "P-384")
        nid = NID_secp384r1;
    else
        throw CryptoException(CryptoException::Reason::Crypto, "Unsupported curve: " + curve);

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key)
        throw CryptoException(CryptoException::Reason::Crypto, "EC_KEY_new_by_curve_name failed");

    const unsigned char *p = key_data.data();

    if (sign_mode_)
    {
        // Private key (DER)
        pkey_ = d2i_AutoPrivateKey(nullptr, &p, key_data.size());
    }
    else
    {
        // Public key (DER)
        pkey_ = d2i_PUBKEY(nullptr, &p, key_data.size());
    }

    if (!pkey_)
        throw CryptoException(CryptoException::Reason::Crypto, "Key loading failed");
}

OsslEcdsa::~OsslEcdsa()
{
    if (mdctx_)
    {
        EVP_MD_CTX_free(mdctx_);
        mdctx_ = nullptr;
    }
    if (pkey_)
    {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
}

void OsslEcdsa::init()
{
    if (initialized_)
        return;

    mdctx_ = EVP_MD_CTX_new();
    if (!mdctx_)
        throw CryptoException(CryptoException::Reason::Crypto, "EVP_MD_CTX_new failed");

    const EVP_MD *md = nullptr;

    // Select digest based on curve size (optional but correct)
    int bits = EVP_PKEY_bits(pkey_);
    if (bits <= 256)
        md = EVP_sha256();
    else if (bits <= 384)
        md = EVP_sha384();
    else
        throw CryptoException(CryptoException::Reason::Crypto, "Unsupported EC key size");

    if (sign_mode_)
    {
        if (EVP_DigestSignInit(mdctx_, nullptr, md, nullptr, pkey_) <= 0)
            throw CryptoException(CryptoException::Reason::Crypto, "EVP_DigestSignInit failed");
    }
    else
    {
        if (EVP_DigestVerifyInit(mdctx_, nullptr, md, nullptr, pkey_) <= 0)
            throw CryptoException(CryptoException::Reason::Crypto, "EVP_DigestVerifyInit failed");
    }

    initialized_ = true;
}

void OsslEcdsa::update(const uint8_t *data, size_t len)
{
    if (!initialized_)
        throw CryptoException(CryptoException::Reason::Crypto, "Must call init() first");

    if (sign_mode_)
    {
        if (EVP_DigestSignUpdate(mdctx_, data, len) <= 0)
            throw CryptoException(CryptoException::Reason::Crypto, "EVP_DigestSignUpdate failed");
    }
    else
    {
        if (EVP_DigestVerifyUpdate(mdctx_, data, len) <= 0)
            throw CryptoException(CryptoException::Reason::Crypto, "EVP_DigestVerifyUpdate failed");
    }
}

SecureVector OsslEcdsa::finish()
{
    if (!initialized_)
        throw CryptoException(CryptoException::Reason::Crypto, "Must call init() first");

    SecureVector result;

    if (sign_mode_)
    {
        size_t sig_len = 0;

        if (EVP_DigestSignFinal(mdctx_, nullptr, &sig_len) <= 0)
            throw CryptoException(CryptoException::Reason::Crypto, "EVP_DigestSignFinal(size) failed");

        result.resize(sig_len);

        if (EVP_DigestSignFinal(mdctx_, result.data(), &sig_len) <= 0)
            throw CryptoException(CryptoException::Reason::Crypto, "EVP_DigestSignFinal(data) failed");

        return result;
    }

    // Verification handled separately
    throw CryptoException(CryptoException::Reason::Crypto, "finish() called in verify mode");
}

bool OsslEcdsa::verify(const uint8_t *sig, size_t sig_len)
{
    if (!initialized_ || sign_mode_)
        throw CryptoException(CryptoException::Reason::Crypto, "verify() called in invalid state");

    int rc = EVP_DigestVerifyFinal(mdctx_, sig, sig_len);
    return rc == 1;
}

std::unique_ptr<ICryptoOperation> OpenSSLBackend::createECDSA(const std::string &curve,
                                                              bool sign_mode,
                                                              const SecureVector &key_data)
{
    LOG_ENTRY("curve=%s, sign=%d", curve.c_str(), sign_mode);
    return std::make_unique<OsslEcdsa>(curve, sign_mode, key_data);
}
