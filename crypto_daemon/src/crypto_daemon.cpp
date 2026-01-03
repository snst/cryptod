// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "crypto_daemon.h"
#include <getopt.h>
#include "crypto_globals.h"
#include "crypto_service.h"
#include "ossl_backend.h"

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

    crypto_backend = std::make_unique<OpenSSLBackend>();
}

int CryptoDaemon::run()
{
    unlink(CRYPTOD_SOCKET_PATH);

    capnp::EzRpcServer server(kj::heap<CryptoServiceImpl>(crypto_backend.get(), &keystore), CRYPTOD_SOCKET_RPC);

    LOG_INFO("Crypto Daemon listening on %s...", CRYPTOD_SOCKET_RPC);

    // EzRpcServer provides its own WaitScope.
    // We wait on a promise that never resolves to keep the daemon alive.
    kj::NEVER_DONE.wait(server.getWaitScope());
    return 0;
}

/*
bool updateCred()
{
    struct ucred cred{};
    socklen_t cred_len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == -1)
    {
        LOG_ERROR("getsockopt, failed to get uid.. fd=%d", fd);
        return false;
    }
    else
    {
        pid = cred.pid;
        uid = cred.uid;
        gid = cred.gid;
        label = "fd=" + std::to_string(fd) + " pid=" + std::to_string(pid) + " uid=" + std::to_string(uid) + " gid=" + std::to_string(gid);
        LOG_INFO("Client connected: %s", label.c_str());
        return true;
    }
}
*/
