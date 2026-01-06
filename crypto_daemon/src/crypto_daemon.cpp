// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "crypto_daemon.h"
#include <getopt.h>
#include "crypto_globals.h"
#include "log_macro.h"
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
            throw CryptoException(crypto_code_t::INVALID_VALUE, "Command line error");
        }
    }

    if (configFile.empty())
        throw CryptoException(crypto_code_t::INVALID_VALUE, "Missing config file. Parameter: -c FILENAME");

    config.load(configFile);
    keystore.setMasterKey(config.masterKey());
    keystore.loadStore(config.keystoreFile());
    keystore.setCacheKeys(config.cacheKeys() != 0);
}

int CryptoDaemon::run()
{
#ifdef USE_RPC_CAPNP
    CapnpCryptoService service(crypto_backend, keystore);
#endif
#ifdef USE_RPC_SOCKET
    SocketCryptoService service(crypto_backend, keystore);
#endif
    return service.run(CRYPTOD_SOCKET_PATH);
}
