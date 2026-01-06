// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <getopt.h>
#include "keystore.h"
#include "helpers.h"
#include "crypto_config.h"
#include "log_macro.h"

class App
{
public:
    int run(int argc, char *argv[])
    {
        const option long_opts[] = {
            {"config", required_argument, nullptr, 'c'},
            {"verbose", no_argument, nullptr, 'v'},
            {"help", no_argument, nullptr, 'h'},
            {"list", no_argument, nullptr, 'l'},
            {"key", required_argument, nullptr, 'k'},
            {"input", required_argument, nullptr, 'i'},
            {"del", no_argument, nullptr, 'd'},
            {"add", no_argument, nullptr, 'a'},
            {nullptr, 0, nullptr, 0}};

        int opt;
        while ((opt = getopt_long(argc, argv, "i:k:c:vhlda", long_opts, nullptr)) != -1)
        {
            switch (opt)
            {
            case 'c':
                configFile = optarg;
                break;
            case 'i':
                inputFile = optarg;
                break;
            case 'k':
                try
                {
                    unsigned long v = std::stoul(optarg, nullptr, 0); // base 0 auto-detects "0x" hex
                    keyId = static_cast<uint32_t>(v);
                }
                catch (const std::exception &)
                {
                    throw CryptoException(crypto_code_t::INVALID_VALUE, "Invalid KeyId (decimal or 0xHEX expected)");
                }
                break;
            case 'v':
                std::cout << "Verbose enabled\n";
                break;
            case 'h':
                std::cout << "Usage: ...\n";
                return 0;
            case 'l':
                cmdList = true;
                break;
            case 'a':
                cmdAdd = true;
                break;
            case 'd':
                cmdDelete = true;
                break;
            case ':':
            case '?':
            default:
                throw CryptoException(crypto_code_t::INVALID_VALUE, "Command line error");
            }
        }

        if (configFile.empty())
            throw CryptoException(crypto_code_t::INVALID_VALUE, "Missing config file. Parameter: -c FILENAME");

        config.load(configFile);
        keystore.setMasterKey(config.masterKey());
        keystore.loadStore(config.keystoreFile());

        if (!inputFile.empty())
        {
            LOG_INFO("Load input: %s", inputFile.c_str());
            inputData = load_file(inputFile);
        }

        if (cmdDelete)
        {
            doDelKey();
        }

        if (cmdAdd)
        {
            doAddKey();
        }

        if (cmdList)
        {
            doListKeys();
        }

        return 0;
    }

private:
    KeyStore keystore;
    CryptoConfig config;
    std::string configFile;
    std::string inputFile;
    bool cmdList = false;
    bool cmdDelete = false;
    uint32_t keyId = 0U;
    bool cmdAdd = false;
    SecureVector inputData;

    bool checkKeyId()
    {
        if (!keyId)
        {
            LOG_ERROR("KeyId missing: -k id");
            return false;
        }
        return true;
    }

    bool checkInputData()
    {
        if (inputData.size() == 0)
        {
            LOG_ERROR("KeyData missing: -i inputfile");
            return false;
        }
        return true;
    }

    void saveKeyStore()
    {
        keystore.saveStore(config.keystoreFile());
    }

    void doDelKey()
    {
        LOG_INFO("Del key");
        if (!checkKeyId())
            return;
        keystore.deleteKey(keyId);
        saveKeyStore();
    }

    void doAddKey()
    {
        LOG_INFO("Add key");
        if (!checkKeyId() || !checkInputData())
            return;
        keystore.addKey(keyId, KeyType::Symmetric, 0, inputData);
        saveKeyStore();
    }

    void doListKeys()
    {
        auto keyIds = keystore.getKeyIdList();
        int w = 15;
        for (auto id : keyIds)
        {
            std::cout << std::left;
            std::cout << std::setw(w) << "KeyId:   " << id << ", 0x" << std::hex << id << std::dec << std::endl;
            auto keyEntry = keystore.getKeyEntry(id);
            if (keyEntry)
            {

                std::cout << std::setw(w) << "KeyType:" << (uint32_t)(keyEntry->metadata.keyType) << std::endl;
                std::cout << std::setw(w) << "KeySizeBits:" << (uint32_t)(keyEntry->metadata.keySizeBits) << std::endl;
                std::cout << std::setw(w) << "CreationTime:" << (uint64_t)(keyEntry->metadata.creationTime) << std::endl;
                std::cout << std::setw(w) << "UidCount:" << (uint32_t)(keyEntry->metadata.uidCount) << std::endl;
                std::cout << std::setw(w) << "GidCount:" << (uint32_t)(keyEntry->metadata.gidCount) << std::endl;
                std::cout << std::setw(w) << "IV:" << hexToString(keyEntry->iv.vector()) << std::endl;
                std::cout << std::setw(w) << "AuthTag:" << hexToString(keyEntry->authTag.vector()) << std::endl;
                std::cout << std::setw(w) << "EncyptedKey:" << hexToString(keyEntry->encryptedKey.vector()) << std::endl;
                std::cout << std::setw(w) << "PlainKey:" << hexToString(keystore.getKey(id).data.vector()) << std::endl;
            }
            std::cout << std::endl;
        }
    }
};

int main(int argc, char *argv[])
{
    try
    {
        App app;
        return app.run(argc, argv);
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
    }
}
