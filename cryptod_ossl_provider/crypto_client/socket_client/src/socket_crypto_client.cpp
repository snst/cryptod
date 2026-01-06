
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

class CryptoSocketContext
{
public:
    UnixSocket socket_;
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
    return false;
}

void cc_send_init(CryptoSocketContext *ctx, crypto_op_type_t op_type, const void *payload, uint32_t payload_len)
{
    ctx->request.magic = CRYPTO_MAGIC_REQ;
    ctx->request.version = CRYPTO_PROTO_VERSION;
    ctx->request.op_type = op_type;
    ctx->request.op_step = STEP_INIT;

    cc_send_request(ctx, payload, payload_len);
}

int cc_hmac_init(void *context, crypto_key_id_t key_id, crypto_hash_alg_t hash_alg)
{
    try
    {
        CryptoSocketContext *ctx = (CryptoSocketContext *)context;
        LOG_ENTRY("ctx=%p, fd=%d, key_id=%d, hash_alg=%d", ctx, ctx->fd(), key_id, hash_alg);

        if (unexpected_msg_received(ctx))
        {
            LOG_ERROR("unexpected message received before cc_hmac_init");
            return 0;
        }

        struct hmac_params params = {.key_id = key_id, .hash_alg = hash_alg};
        cc_send_init(ctx, OP_TYPE_HMAC, &params, sizeof(params));
        return 1;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
    }
    return 0;
}

int cc_hmac_update(void *context, const uint8_t *data, uint32_t len)
{
    try
    {
        CryptoSocketContext *ctx = (CryptoSocketContext *)context;
        LOG_ENTRY("ctx=%p, fd=%d, len=%u", ctx, ctx->fd(), len);

        if (unexpected_msg_received(ctx))
        {
            LOG_ERROR("unexpected message received before cc_hmac_update");
            return 0;
        }

        ctx->request.op_step = STEP_UPDATE;
        cc_send_request(ctx, data, len);
        return 1;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
    }
    return 0;
}

int cc_hmac_final(void *context, uint8_t *out, uint32_t *out_len)
{
    try
    {
        CryptoSocketContext *ctx = (CryptoSocketContext *)context;
        LOG_ENTRY("ctx=%p, socket=%d, out_len=%u", ctx, ctx->fd(), *len);
        uint32_t max_hmac_len = *out_len;
        *out_len = 0;

        if (unexpected_msg_received(ctx))
        {
            LOG_ERROR("unexpected message received before cc_hmac_update");
            return 0;
        }

        ctx->request.op_step = STEP_FINISH;
        cc_send_request(ctx, NULL, 0);

        if (!cc_read_response(ctx, 3000))
        {
            LOG_ERROR("Timeout to receive cc_hmac_final answer");
            return 0;
        }

        if (!valid_crypto_msg_res(&ctx->response))
        {
            LOG_ERROR("Invalid cc_hmac_final response packet");
            return 0;
        }

        if (!valid_crypto_msg_ok(&ctx->response))
        {
            LOG_ERROR("cc_hmac_final response not ok");
            return 0;
        }

        if ((ctx->response.payload_len == 0) || (ctx->response.payload_len > 128) || (ctx->response.payload_len > max_hmac_len))
        {
            LOG_ERROR("cc_hmac_final invalid payload len %u", ctx->response.payload_len);
            return 0;
        }

        if (!ctx->socket_.recv(out, ctx->response.payload_len, 3000))
        {
            LOG_ERROR("Timeout to receive cc_hmac_final payload");
            return 0;
        }

        *out_len = ctx->response.payload_len;
        return 1;
    }
    catch (const CryptoException &e)
    {
        LOG_EXCEPTION(e.what());
    }
    return 0;
}
