
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include "crypto_daemon.h"
#include "log_macro.h"

int main(int argc, char *argv[])
{
    try
    {
        CryptoDaemon daemon;
        daemon.init(argc, argv);
        return daemon.run();
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
    }
}
