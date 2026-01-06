
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

#define RECV_TIMEOUT 3000

static uint32_t next_session_id = 0;

class CryptoSocketContext
{
public:
    UnixSocket socket_;
    uint32_t session_id_;
    struct crypto_msg_header request;
    struct crypto_msg_header response;
};

void cc_send_request(CryptoSocketContext *ctx, const void *payload, uint32_t payload_len)
{
    LOG_ENTRY("ctx=%p, fd=%d, op_type=%d, op_step=%d, payload_len=%u",
              ctx, ctx->fd(), ctx->request.op_type, ctx->request.op_step, payload_len);

    ctx->request.payload_len = payload_len;

    // Send Header
    ctx->socket_.send(&ctx->request, sizeof(struct crypto_msg_header));

    // Send Payload if exists
    if (payload && ctx->request.payload_len > 0)
    {
        ctx->socket_.send(payload, payload_len);
    }
}

bool cc_read_response(CryptoSocketContext *ctx, int32_t timeout)
{
    bool ret = ctx->socket_.recv(&ctx->response, sizeof(crypto_msg_header), timeout);
    if (ret)
    {
        if (!valid_crypto_msg_res(&ctx->response))
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
    delete ctx;
}

bool unexpected_msg_received(CryptoSocketContext *ctx)
{
    if (cc_read_response(ctx, 0))
    {
        LOG_ERROR("Unexpected msg received: %d", ctx->response.status);
        return true;
    }
    return false;
}

void throw_if_unexpected_message_received(CryptoSocketContext *ctx)
{
    if (cc_read_response(ctx, 0))
    {
        throw CryptoException((crypto_code_t)ctx->response.status, "Unexpected response received: " + std::to_string(ctx->response.status));
    }
}

void cc_send_init(CryptoSocketContext *ctx, crypto_op_type_t op_type, const void *payload, uint32_t payload_len)
{
    ctx->request.magic = CRYPTO_MAGIC_REQ;
    ctx->request.version = CRYPTO_PROTO_VERSION;
    ctx->session_id_ = ctx->session_id_;
    ctx->request.op_type = op_type;
    ctx->request.op_step = STEP_INIT;

    cc_send_request(ctx, payload, payload_len);
}

crypto_code_t cc_hmac_init(void *context, crypto_key_id_t key_id, crypto_hash_alg_t hash_alg)
{
    try
    {
        CryptoSocketContext *ctx = (CryptoSocketContext *)context;
        ctx->session_id_ = next_session_id++;
        LOG_ENTRY("ctx=%p, fd=%d, session_id=%u, key_id=%d, hash_alg=%d", ctx, ctx->fd(), ctx->session_id_, key_id, hash_alg);

        throw_if_unexpected_message_received(ctx);

        struct hmac_params params = {.key_id = key_id, .hash_alg = hash_alg};
        cc_send_init(ctx, OP_TYPE_HMAC, &params, sizeof(params));
        return crypto_code_t::OK;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        return e.reason();
    }
}

crypto_code_t cc_hmac_update(void *context, const uint8_t *data, uint32_t len)
{
    try
    {
        CryptoSocketContext *ctx = (CryptoSocketContext *)context;
        LOG_ENTRY("ctx=%p, fd=%d, len=%u", ctx, ctx->fd(), len);

        throw_if_unexpected_message_received(ctx);

        ctx->request.op_step = STEP_UPDATE;
        cc_send_request(ctx, data, len);
        return crypto_code_t::OK;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        return e.reason();
    }
}

crypto_code_t cc_hmac_final(void *context, uint8_t *out, uint32_t *out_len)
{
    try
    {
        CryptoSocketContext *ctx = (CryptoSocketContext *)context;
        LOG_ENTRY("ctx=%p, socket=%d, out_len=%u", ctx, ctx->fd(), *len);
        uint32_t max_hmac_len = *out_len;
        *out_len = 0;

        throw_if_unexpected_message_received(ctx);

        ctx->request.op_step = STEP_FINISH;
        cc_send_request(ctx, NULL, 0);

        if (!cc_read_response(ctx, RECV_TIMEOUT))
        {
            LOG_ERROR("Timeout to receive cc_hmac_final answer");
            return crypto_code_t::COM_ERROR;
        }

        if (!valid_crypto_msg_res(&ctx->response))
        {
            LOG_ERROR("Invalid cc_hmac_final response packet");
            return crypto_code_t::COM_ERROR;
        }

        if (!valid_crypto_msg_ok(&ctx->response))
        {
            LOG_ERROR("cc_hmac_final response not ok: %d, %s", ctx->response.status, cc_to_str((crypto_code_t)ctx->response.status));
            return (crypto_code_t)ctx->response.status;
        }

        if ((ctx->response.payload_len == 0) || (ctx->response.payload_len > 128) || (ctx->response.payload_len > max_hmac_len))
        {
            LOG_ERROR("cc_hmac_final invalid payload len %u", ctx->response.payload_len);
            return crypto_code_t::COM_ERROR;
        }

        if (!ctx->socket_.recv(out, ctx->response.payload_len, RECV_TIMEOUT))
        {
            LOG_ERROR("Timeout to receive cc_hmac_final payload");
            return crypto_code_t::COM_ERROR;
        }

        *out_len = ctx->response.payload_len;
        return crypto_code_t::OK;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
        return e.reason();
    }
}
