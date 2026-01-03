

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <memory>
#include "log_macro.h"
#include "crypto_service.h"

CryptoServiceImpl::CryptoServiceImpl(ICryptoBackend *crypto_backend, IKeyStore *keystore)
    : crypto_backend_(crypto_backend), keystore_(keystore)
{
}

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

kj::Promise<void> CryptoServiceImpl::initHmac(InitHmacContext context)
{
    auto params = context.getParams();

    auto key_res = keystore_->getKey(params.getKeyId());
    auto hashMode = rpc_hash_mode_to_backend(params.getMode());
    auto op = crypto_backend_->createHMAC(hashMode, key_res.data);

    // Returning a new session object (Capability)
    context.getResults().setSession(
        kj::heap<HmacSessionImpl>(std::move(op)));
    return kj::READY_NOW;
}
