// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "crypto_daemon.h"
#include <getopt.h>
#include "crypto_globals.h"
#include "capnp_crypto_service.h"
#include "ossl_backend.h"
#include "dummy_backend.h"

#define ENABLE_LOGGING
#include "log_macro.h"

void CryptoDaemon::init(int argc, char *argv[])
{
    std::string configFile;
    const option long_opts[] = {
        {"config", required_argument, nullptr, 'c'},
        {nullptr, 0, nullptr, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "c:d", long_opts, nullptr)) != -1)
    {
        switch (opt)
        {
        case 'c':
            configFile = optarg;
            break;
        case ':':
        case '?':
        default:
            throw CryptoException(CryptoException::Reason::InvalidValue, "Command line error");
        }
    }

    if (configFile.empty())
        throw CryptoException(CryptoException::Reason::General, "Missing config file. Parameter: -c FILENAME");

    config.load(configFile);
    keystore.setMasterKey(config.masterKey());
    keystore.loadStore(config.keystoreFile());
    keystore.setCacheKeys(config.cacheKeys() != 0);

    crypto_backend = std::make_unique<OpenSSLBackend>();
    // crypto_backend = std::make_unique<DummyBackend>();
}

int CryptoDaemon::run()
{
    CapnpService service;
    return service.run(crypto_backend.get(), &keystore, CRYPTOD_SOCKET_PATH);
}
