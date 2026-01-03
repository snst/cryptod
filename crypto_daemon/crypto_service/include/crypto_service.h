
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <iostream>
#include <unistd.h>
#include "crypto_backend.h"
#include <capnp/ez-rpc.h>
#include "crypto.capnp.h"
#include "ikeystore.h"

class HmacSessionImpl final : public CryptoService::HmacSession::Server
{
public:
    HmacSessionImpl(std::unique_ptr<ICryptoOperation> op);
    kj::Promise<void> update(UpdateContext context) override;
    kj::Promise<void> final(FinalContext context) override;

private:
    std::unique_ptr<ICryptoOperation> op_;
};

class CryptoServiceImpl final : public CryptoService::Server
{
public:
    CryptoServiceImpl(ICryptoBackend* crypto_backend, IKeyStore* keystore);
    kj::Promise<void> initHmac(InitHmacContext context) override;
    ICryptoBackend* crypto_backend_;
    IKeyStore* keystore_;
};
