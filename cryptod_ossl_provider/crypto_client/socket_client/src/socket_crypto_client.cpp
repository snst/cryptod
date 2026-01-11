
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/ioctl.h>
#include "crypto_socket_hdr.h"
#include "icrypto_client.h"
#include "crypto_globals.h"
#include "log_macro.h"
#include "unix_socket.h"

#define RECV_TIMEOUT -1

#define SOCKET_CTX(x) ((CryptoSocketContext *)x->rpc_)

class CryptoSocketContext
{
public:
    UnixSocket socket_;
};

void cc_send_request(rpc_hmac_t *hmac_ctx, crypto_msg_header_t &request, const void *payload, size_t payload_len)
{
    CryptoSocketContext *socket_ctx = SOCKET_CTX(hmac_ctx);
    LOG_ENTRY("hmac_ctx=%p, fd=%d, op_type=%d, op_step=%d, payload_len=%u",
              hmac_ctx, socket_ctx->fd(), request.op_type, request.op_step, payload_len);

    request.magic = CRYPTO_MAGIC_REQ;
    request.version = CRYPTO_PROTO_VERSION;
    request.session_id = hmac_ctx->session_id_;
    request.payload_len = payload_len;
    request.status = crypto_code_t::OK;

    // Send Header
    socket_ctx->socket_.send(&request, sizeof(request));

    // Send Payload if exists
    if (payload && request.payload_len > 0)
    {
        socket_ctx->socket_.send(payload, payload_len);
    }
}

bool cc_read_response(rpc_hmac_t *hmac_ctx, crypto_msg_header_t &response, int32_t timeout)
{
    bool ret = SOCKET_CTX(hmac_ctx)->socket_.recvComplete(&response, sizeof(crypto_msg_header_t), timeout);
    if (ret)
    {
        if (!valid_crypto_msg_res(&response))
        {
            throw CryptoException(crypto_code_t::COM_ERROR, "Corrupted response packet received");
        }
    }
    return ret;
}

void *cc_connect()
{
    CryptoSocketContext *ctx = NULL;
    try
    {
        ctx = new CryptoSocketContext();
        if (!ctx)
        {
            LOG_ERROR("Failed to create CryptoSocketContext");
        }
        else
        {
            ctx->socket_.connect(CRYPTOD_SOCKET_PATH);
        }
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        if (ctx)
        {
            delete ctx;
            ctx = NULL;
        }
    }
    LOG_EXIT("ctx=%p, fd=%d", ctx, ctx->fd());
    return ctx;
}

void cc_disconnect(void *context)
{
    CryptoSocketContext *ctx = (CryptoSocketContext *)context;
    LOG_ENTRY("ctx=%p, fd=%d", ctx, ctx->fd());
    ctx->socket_.disconnect();
    delete ctx;
}

void throw_if_unexpected_message_received(rpc_hmac_t *hmac_ctx)
{
    crypto_msg_header_t response = {0};
    if (cc_read_response(hmac_ctx, response, 0))
    {
        throw CryptoException((crypto_code_t)response.status, "Unexpected response received: " + std::to_string(response.status));
    }
}

crypto_code_t cc_hmac_init(rpc_hmac_t *hmac_ctx)
{
    try
    {
        CryptoSocketContext *socket_ctx = SOCKET_CTX(hmac_ctx);
        LOG_ENTRY("hmac_ctx=%p, fd=%d, session_id=%u, key_id=%d, hash_alg=%d", hmac_ctx, socket_ctx->fd(), hmac_ctx->session_id_, key_id, hash_alg);

        throw_if_unexpected_message_received(hmac_ctx);

        crypto_msg_header_t request = {.op_type = OP_TYPE_HMAC, .op_step = STEP_INIT};
        struct hmac_params params = {.key_id = hmac_ctx->key_id_, .hash_alg = hmac_ctx->hash_alg_};
        cc_send_request(hmac_ctx, request, &params, sizeof(params));
        return crypto_code_t::OK;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        return e.reason();
    }
}

crypto_code_t cc_hmac_update(rpc_hmac_t *hmac_ctx, const uint8_t *data, uint32_t len)
{
    try
    {
        CryptoSocketContext *socket_ctx = SOCKET_CTX(hmac_ctx);
        LOG_ENTRY("hmac_ctx=%p, fd=%d, len=%u", hmac_ctx, socket_ctx->fd(), len);

        throw_if_unexpected_message_received(hmac_ctx);

        crypto_msg_header_t request = {.op_type = OP_TYPE_HMAC, .op_step = STEP_UPDATE};
        cc_send_request(hmac_ctx, request, data, len);
        return crypto_code_t::OK;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        return e.reason();
    }
}

crypto_code_t cc_hmac_final(rpc_hmac_t *hmac_ctx, uint8_t *out, uint32_t *out_len)
{
    try
    {
        CryptoSocketContext *socket_ctx = SOCKET_CTX(hmac_ctx);
        LOG_ENTRY("ctx=%p, socket=%d, out_len=%u", ctx, ctx->fd(), *len);
        uint32_t max_hmac_len = *out_len;
        *out_len = 0;

        throw_if_unexpected_message_received(hmac_ctx);

        crypto_msg_header_t request = {.op_type = OP_TYPE_HMAC, .op_step = STEP_FINAL};

        request.op_step = STEP_FINAL;
        cc_send_request(hmac_ctx, request, NULL, 0);

        crypto_msg_header_t response = {0};
        if (!cc_read_response(hmac_ctx, response, RECV_TIMEOUT))
        {
            LOG_ERROR("Timeout to receive cc_hmac_final answer");
            return crypto_code_t::COM_ERROR;
        }

        if (!valid_crypto_msg_res(&response))
        {
            LOG_ERROR("Invalid cc_hmac_final response packet");
            return crypto_code_t::COM_ERROR;
        }

        if (!valid_crypto_msg_ok(&response))
        {
            LOG_ERROR("cc_hmac_final response not ok: %d, %s", response.status, cc_to_str((crypto_code_t)response.status));
            return (crypto_code_t)response.status;
        }

        if ((response.payload_len == 0) || (response.payload_len > 128) || (response.payload_len > max_hmac_len))
        {
            LOG_ERROR("cc_hmac_final invalid payload len %u", response.payload_len);
            return crypto_code_t::COM_ERROR;
        }

        if (!socket_ctx->socket_.recvComplete(out, response.payload_len, RECV_TIMEOUT))
        {
            LOG_ERROR("Timeout to receive cc_hmac_final payload");
            return crypto_code_t::COM_ERROR;
        }

        *out_len = response.payload_len;
        return crypto_code_t::OK;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        return e.reason();
    }
}
