
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "keystore.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <fstream>
#include <cstring>

bool KeyEntry::hasPermission(uint32_t uid, uint32_t gid, KeyPermission perm) const
{
    uint32_t p = static_cast<uint32_t>(perm);
    // UID entries first
    for (size_t i = 0; i < metadata.uidCount; ++i)
    {
        if (metadata.acl[i].id == uid && (metadata.acl[i].permissions & p))
            return true;
    }
    // GID entries after UID
    for (size_t i = metadata.uidCount; i < metadata.uidCount + metadata.gidCount; ++i)
    {
        if (metadata.acl[i].id == gid && (metadata.acl[i].permissions & p))
            return true;
    }
    return false;
}

KeyStore::KeyStore()
{
}

void KeyStore::setMasterKey(const SecureVector &masterKey)
{
    deriveKeys(masterKey);
}

void KeyStore::clear()
{
    entries_.clear();
}

void KeyStore::deriveKeys(const SecureVector &masterKey)
{
    encKey_ = masterKey;
    authKey_ = masterKey;
}

void KeyStore::encryptKey(const SecureVector &plaintext,
                          const SecureVector &key,
                          const SecureVector &iv,
                          const KeyMetadata &meta,
                          SecureVector &ciphertext,
                          SecureVector &tag)
{
    ciphertext.resize(plaintext.size());
    tag.resize(AUTH_TAG_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    EVP_EncryptUpdate(ctx, nullptr, &len,
                      reinterpret_cast<const uint8_t *>(&meta), sizeof(meta));

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      plaintext.data(), plaintext.size());

    EVP_EncryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_SIZE, tag.data());

    EVP_CIPHER_CTX_free(ctx);
}

SecureVector KeyStore::decryptKey(const SecureVector &ciphertext,
                                  const SecureVector &key,
                                  const SecureVector &iv,
                                  const KeyMetadata &meta,
                                  const SecureVector &tag)
{
    SecureVector plaintext(ciphertext.size());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    EVP_DecryptUpdate(ctx, nullptr, &len,
                      reinterpret_cast<const uint8_t *>(&meta), sizeof(meta));

    EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                      ciphertext.data(), ciphertext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                        const_cast<uint8_t *>(tag.data()));

    if (EVP_DecryptFinal_ex(ctx, nullptr, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Authentication failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

void KeyStore::addKey(uint32_t keyId, KeyType type, uint32_t sizeBits,
                      const SecureVector &rawKey,
                      const std::vector<AclEntry> &uidAcl,
                      const std::vector<AclEntry> &gidAcl)
{
    if (entries_.count(keyId))
        throw std::runtime_error("KeyId exists");

    KeyEntry entry{};
    entry.keyId = keyId;
    entry.metadata.keyId = keyId;
    entry.metadata.keyType = type;
    entry.metadata.keySizeBits = sizeBits;
    entry.metadata.creationTime = std::time(nullptr);
    entry.iv.resize(IV_SIZE);
    RAND_bytes(entry.iv.data(), entry.iv.size());

    // Copy ACLs
    entry.metadata.uidCount = uidAcl.size();
    entry.metadata.gidCount = gidAcl.size();
    if ((uidAcl.size() + gidAcl.size()) > MAX_ACL)
        throw std::runtime_error("Too many ACL entries");

    for (size_t i = 0; i < uidAcl.size(); ++i)
        entry.metadata.acl[i] = uidAcl[i];
    for (size_t i = 0; i < gidAcl.size(); ++i)
        entry.metadata.acl[uidAcl.size() + i] = gidAcl[i];

    // Encrypt key
    encryptKey(rawKey, encKey_, entry.iv, entry.metadata,
               entry.encryptedKey, entry.authTag);

    entries_[keyId] = std::move(entry);
}

bool KeyStore::saveStore(const std::string &path)
{
    std::ofstream f(path, std::ios::binary);
    if (!f)
        return false;

    uint32_t count = entries_.size();
    f.write(reinterpret_cast<char *>(&count), sizeof(count));

    for (auto &kv : entries_)
    {
        auto &e = kv.second;
        f.write(reinterpret_cast<char *>(&e.keyId), sizeof(e.keyId));
        f.write(reinterpret_cast<char *>(&e.metadata), sizeof(e.metadata));
        f.write(reinterpret_cast<char *>(e.iv.data()), e.iv.size());
        uint32_t keylen = e.encryptedKey.size();
        f.write(reinterpret_cast<char *>(&keylen), sizeof(keylen));
        f.write(reinterpret_cast<char *>(e.encryptedKey.data()), keylen);
        f.write(reinterpret_cast<char *>(e.authTag.data()), e.authTag.size());
    }
    return true;
}

bool KeyStore::loadStore(const std::string &path)
{
    LOG_INFO("Loading keystore: %s", path.c_str());
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;

    entries_.clear();
    uint32_t count;
    f.read(reinterpret_cast<char *>(&count), sizeof(count));

    for (uint32_t i = 0; i < count; ++i)
    {
        KeyEntry e{};
        e.iv.resize(IV_SIZE);
        e.authTag.resize(AUTH_TAG_SIZE);
        f.read(reinterpret_cast<char *>(&e.keyId), sizeof(e.keyId));
        f.read(reinterpret_cast<char *>(&e.metadata), sizeof(e.metadata));
        f.read(reinterpret_cast<char *>(e.iv.data()), e.iv.size());

        uint32_t keylen;
        f.read(reinterpret_cast<char *>(&keylen), sizeof(keylen));
        e.encryptedKey.resize(keylen);
        f.read(reinterpret_cast<char *>(e.encryptedKey.data()), keylen);
        f.read(reinterpret_cast<char *>(e.authTag.data()), e.authTag.size());

        entries_[e.keyId] = std::move(e);
    }

    return true;
}

std::vector<uint32_t> KeyStore::getKeyIdList()
{
    std::vector<uint32_t> ids;
    ids.reserve(entries_.size());
    for (const auto &kv : entries_)
        ids.push_back(kv.first);
    return ids;
}

void KeyStore::deleteKey(uint32_t keyId)
{
    auto it = entries_.find(keyId);
    if (it == entries_.end())
        throw std::runtime_error("KeyId not existing");

    entries_.erase(it);
}

KeyEntry *KeyStore::getKeyEntry(uint32_t keyId)
{
    auto it = entries_.find(keyId);
    if (it == entries_.end())
        return nullptr;
    return &it->second;
}

Result KeyStore::getKeyWithAccessCheck(uint32_t keyId, uint32_t uid, uint32_t gid, KeyPermission perm)
{
    auto it = entries_.find(keyId);
    if (it == entries_.end())
        return Result(ResultStatus::NotFound);

    KeyEntry &entry = it->second;
    if (!entry.hasPermission(uid, gid, perm))
        return Result(ResultStatus::PermissionDenied);

    try
    {
        SecureVector key = decryptKey(it->second.encryptedKey,
                                      encKey_,
                                      it->second.iv,
                                      it->second.metadata,
                                      it->second.authTag);
        return Result(ResultStatus::Ok, std::move(key));
    }
    catch (...)
    {
        return Result(ResultStatus::CryptoError);
    }
}

Result KeyStore::getKey(uint32_t keyId)
{
    auto it = entries_.find(keyId);
    if (it == entries_.end())
        return Result(ResultStatus::NotFound);

    try
    {
        SecureVector key = decryptKey(it->second.encryptedKey,
                                      encKey_,
                                      it->second.iv,
                                      it->second.metadata,
                                      it->second.authTag);
        return Result(ResultStatus::Ok, std::move(key));
    }
    catch (...)
    {
        return Result(ResultStatus::CryptoError);
    }
}
