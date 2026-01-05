
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <unordered_map>
#include <ctime>
#include "ikeystore.h"
#include "secure_vector.h"
#include "log_macro.h"

enum class KeyType : uint8_t
{
    Symmetric = 1,
    ECC_Private = 2,
    ECC_Public = 3,
    ECC_KeyPair = 4,
    RSA_Private = 5,
    RSA_Public = 6,
    RSA_KeyPair = 7
};

enum class KeyPermission : uint16_t
{
    Encrypt = 1 << 0,
    Decrypt = 1 << 1,
    Sign = 1 << 2,
    Verify = 1 << 3,
    Derive = 1 << 4,
    Export = 1 << 5,
    Hmac = 1 << 6
};

struct AclEntry
{
    uint32_t id;          // UID or GID
    uint16_t permissions; // bitmask
};

constexpr size_t MAX_ACL = 16;

constexpr size_t IV_SIZE = 12;
constexpr size_t AUTH_TAG_SIZE = 16;

struct KeyMetadata
{
    uint32_t keyId;
    KeyType keyType;
    uint16_t keySizeBits;
    uint64_t creationTime;

    uint8_t uidCount;
    uint8_t gidCount;

    AclEntry acl[MAX_ACL]; // first UID, then GID
};

struct KeyEntry
{
    uint32_t keyId;
    KeyMetadata metadata;

    SecureVector iv; // 12 bytes
    SecureVector encryptedKey;
    SecureVector authTag; // 16 bytes

    SecureVector decryptedKey; // if cached

    bool hasPermission(uint32_t uid, uint32_t gid, KeyPermission perm) const;
};

class KeyStore : public IKeyStore
{
public:
    explicit KeyStore();
    void setMasterKey(const SecureVector &masterKey);
    void setCacheKeys(bool enable);
    void addKey(uint32_t keyId, KeyType type, uint32_t sizeBits,
                const SecureVector &rawKey,
                const std::vector<AclEntry> &uidAcl = {},
                const std::vector<AclEntry> &gidAcl = {});
    Result getKey(uint32_t keyId);
    Result getKeyWithAccessCheck(uint32_t keyId, uint32_t uid, uint32_t gid, KeyPermission perm);
    std::vector<uint32_t> getKeyIdList();
    KeyEntry *getKeyEntry(uint32_t keyId);
    void deleteKey(uint32_t keyId);
    bool saveStore(const std::string &path);
    bool loadStore(const std::string &path);
    void clear();

private:
    std::unordered_map<uint32_t, KeyEntry> entries_;
    SecureVector encKey_;  // AES-GCM key
    SecureVector authKey_; // reserved for future KDF/HMAC use
    bool cacheKeys;

    void deriveKeys(const SecureVector &masterKey);

    void encryptKey(const SecureVector &plaintext,
                    const SecureVector &key,
                    const SecureVector &iv,
                    const KeyMetadata &meta,
                    SecureVector &ciphertext,
                    SecureVector &tag);

    SecureVector decryptKey(const SecureVector &ciphertext,
                            const SecureVector &key,
                            const SecureVector &iv,
                            const KeyMetadata &meta,
                            const SecureVector &tag);
};
