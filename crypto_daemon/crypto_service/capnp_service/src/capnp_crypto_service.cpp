
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <memory>
#include "capnp_crypto_service.h"
#include "log_macro.h"

HmacSessionImpl::HmacSessionImpl(std::unique_ptr<ICryptoOperation> op) : op_(std::move(op))
{
    op_->init();
}

kj::Promise<void> HmacSessionImpl::update(UpdateContext context)
{
    auto params = context.getParams();
    auto data = params.getData();

    if (data.size() > 0)
    {
        op_->update(data.begin(), data.size());
    }
    return kj::READY_NOW;
}

kj::Promise<void> HmacSessionImpl::final(FinalContext context)
{
    auto hmac = op_->finish();
    context.getResults().setHmac(capnp::Data::Reader((const kj::byte *)hmac.data(), hmac.size()));
    return kj::READY_NOW;
}

static crypto_hash_alg_t rpc_hash_mode_to_backend(::CryptoService::HashMode mode)
{
    switch (mode)
    {
    case ::CryptoService::HashMode::SHA256:
        return HASH_ALG_SHA256;
    case ::CryptoService::HashMode::SHA384:
        return HASH_ALG_SHA384;
    case ::CryptoService::HashMode::SHA512:
        return HASH_ALG_SHA512;
    default:
        return HASH_ALG_INVALID;
    }
}

CapnpCryptoServiceImpl::CapnpCryptoServiceImpl(ICryptoBackend &crypto_backend, IKeyStore &keystore)
    : crypto_backend_(crypto_backend), keystore_(keystore)
{
}

kj::Promise<void> CapnpCryptoServiceImpl::initHmac(InitHmacContext context)
{
    auto params = context.getParams();

    auto key_res = keystore_.getKey(params.getKeyId());
    auto hashMode = rpc_hash_mode_to_backend(params.getMode());
    auto op = crypto_backend_.createHMAC(hashMode, key_res.data);

    // Returning a new session object (Capability)
    context.getResults().setSession(
        kj::heap<HmacSessionImpl>(std::move(op)));
    return kj::READY_NOW;
}

CapnpCryptoService::CapnpCryptoService(ICryptoBackend &crypto_backend, IKeyStore &keystore)
    : CryptoServiceBase(crypto_backend, keystore)
{
}

int32_t CapnpCryptoService::run(std::string path)
{
    unlink(path.c_str());
    std::string connect_str = std::string("unix:") + path;

    capnp::EzRpcServer server(kj::heap<CapnpCryptoServiceImpl>(crypto_backend_, keystore_), connect_str.c_str());

    LOG_INFO("Crypto Daemon using capnp, listening on %s...", connect_str.c_str());

    // EzRpcServer provides its own WaitScope.
    // We wait on a promise that never resolves to keep the daemon alive.
    kj::NEVER_DONE.wait(server.getWaitScope());
    return 0;
}