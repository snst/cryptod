// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "crypto_daemon.h"
#include <getopt.h>
#include "crypto_globals.h"
#include "log_macro.h"
#ifdef USE_CRYPTO_BACKEND_OPENSSL
#include "ossl_backend.h"
#endif
#ifdef USE_CRYPTO_BACKEND_DUMMY
#include "dummy_backend.h"
#endif
#ifdef USE_RPC_CAPNP
#include "capnp_crypto_service.h"
#endif
#ifdef USE_RPC_SOCKET
#include "socket_crypto_service.h"
#endif

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

#ifdef USE_CRYPTO_BACKEND_OPENSSL
    crypto_backend = std::make_unique<OpenSSLBackend>();
#endif
#ifdef USE_CRYPTO_BACKEND_DUMMY
    crypto_backend = std::make_unique<DummyBackend>();
#endif
}

int CryptoDaemon::run()
{
#ifdef USE_RPC_CAPNP
    CapnpCryptoService service;
#endif
#ifdef USE_RPC_SOCKET
    SocketCryptoService service;
#endif
    return service.run(crypto_backend.get(), &keystore, CRYPTOD_SOCKET_PATH);
}
