// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <optional>
#include <capnp/ez-rpc.h>
#include "crypto.capnp.h"
#include "icrypto_client.h"
#include "crypto_globals.h"
#include "log_macro.h"

#define CRYPTOD_SOCKET_RPC "unix:" CRYPTOD_SOCKET_PATH

static ::CryptoService::HashMode backend_hash_mode_to_rpc(crypto_hash_alg_t mode)
{
    switch (mode)
    {
    case HASH_ALG_SHA256:
        return ::CryptoService::HashMode::SHA256;
    case HASH_ALG_SHA384:
        return ::CryptoService::HashMode::SHA384;
    case HASH_ALG_SHA512:
        return ::CryptoService::HashMode::SHA512;
    default:
        return ::CryptoService::HashMode::SHA256;
    }
}

class RPCContext
{
public:
    capnp::EzRpcClient rpcClient;
    kj::WaitScope &waitScope;
    CryptoService::Client service;
    std::optional<CryptoService::HmacSession::Client> session;

    RPCContext()
        : rpcClient(CRYPTOD_SOCKET_RPC),
          waitScope(rpcClient.getWaitScope()),
          service(rpcClient.getMain<CryptoService>())
    {
    }

    ~RPCContext() = default;
};

extern "C" void *cc_connect()
{
    try
    {
        RPCContext *context = new RPCContext();
        return context;
    }
    catch (const kj::Exception &e)
    {
        LOG_ERROR("RPC Error: %s", e.getDescription().cStr());
    }
    return NULL;
}

extern "C" void cc_disconnect(void *vrpc)
{
    try
    {
        RPCContext *rpc = (RPCContext *)vrpc;
        delete rpc;
    }
    catch (const kj::Exception &e)
    {
        LOG_ERROR("RPC Error: %s", e.getDescription().cStr());
    }
}

extern "C" crypto_code_t cc_hmac_init(rpc_hmac_t *hmac_ctx)
{
    RPCContext *rpc = (RPCContext *)hmac_ctx->rpc_;
    try
    {
        auto req = rpc->service.initHmacRequest();
        req.setKeyId(hmac_ctx->key_id_);
        auto hashMode = backend_hash_mode_to_rpc(hmac_ctx->hash_alg_);
        req.setMode(hashMode);
        rpc->session = req.send().getSession();
        return OK;
    }
    catch (const kj::Exception &e)
    {
        LOG_ERROR("RPC Error: %s", e.getDescription().cStr());
    }
    return COM_ERROR;
}

extern "C" crypto_code_t cc_hmac_update(rpc_hmac_t *hmac_ctx, const uint8_t *data, uint32_t size)
{
    RPCContext *rpc = (RPCContext *)hmac_ctx->rpc_;
    try
    {
        auto req = rpc->session.value().updateRequest();
        req.setData(capnp::Data::Reader(data, size));

        // We use .wait() here to make the function synchronous
        auto a = req.send(); //.wait(rpc->waitScope);
        a.wait(rpc->waitScope);

        // auto p = req.send();
        // auto req = rpc->session.value().updateRequest();
        // req.setData(capnp::Data::Reader(data, size));
        // auto p = req.send();

        return OK;
    }
    catch (const kj::Exception &e)
    {
        LOG_ERROR("RPC Error: %s", e.getDescription().cStr());
        return COM_ERROR;
    }
}
extern "C" crypto_code_t cc_hmac_final(rpc_hmac_t *hmac_ctx, uint8_t *data, uint32_t *len)
{
    RPCContext *rpc = (RPCContext *)hmac_ctx->rpc_;
    try
    {
        auto req = rpc->session.value().finalRequest();
        auto result = req.send().wait(rpc->waitScope);

        // Convert binary to Hex string
        auto hmacData = result.getHmac();
        *len = hmacData.size();
        memcpy(data, hmacData.begin(), hmacData.size());

        rpc->session.reset();

        return OK;
    }
    catch (const kj::Exception &e)
    {
        LOG_ERROR("RPC Error: %s", e.getDescription().cStr());
        return COM_ERROR;
    }
}
