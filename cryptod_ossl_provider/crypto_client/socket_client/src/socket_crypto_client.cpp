
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

typedef enum
{
    OK = 0,
    TIMEOUT = 1,
    RESPONSE_ERROR = 2,
    PROTOCOL_ERROR = 3,
    SOCKET_ERROR = 4,
    UNEXPECTED_DATA = 5
} cc_status_t;

typedef struct
{
    int fd;
    struct crypto_msg_header request;
    struct crypto_msg_header response;
} crypto_session_t;

ssize_t cc_readable_bytes(int fd, int32_t timeout)
{
    if (fd < 0)
    {
        LOG_ERROR("Invalid fd");
        return -1;
    }

    // Step 1: Poll to check if fd is readable or closed
    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, timeout); // timeout=0 → non-blocking
    if (ret < 0)
    {
        LOG_ERROR("pol() failed");
        return -1;
    }

    if (ret == 0)
    {
        LOG_EXIT("No data, timeout=%d", timeout);
        return 0;
    }

    // Check for errors / hangup
    /*if (pfd.revents & (POLLERR | POLLHUP))
    {
        return 0; // EOF or error, nothing to read
    }*/

    // Step 2: Query exact number of bytes available
    int bytes_available = 0;
    if (ioctl(fd, FIONREAD, &bytes_available) < 0)
    {
        LOG_ERROR("ioctl(FIONREAD) failed");
        return -1;
    }

    LOG_EXIT("bytes_available=%d, timeout=%d", bytes_available, timeout);
    return bytes_available;
}

cc_status_t cc_read_response(crypto_session_t *s, int32_t timeout)
{
    cc_status_t ret = TIMEOUT;
    ssize_t n = cc_readable_bytes(s->fd, timeout);
    if (n >= sizeof(struct crypto_msg_header))
    {
        n = recv(s->fd, &s->response, sizeof(struct crypto_msg_header), MSG_WAITALL);
        LOG_DEBUG("recv: %ld", n);

        if (n != sizeof(struct crypto_msg_header))
        {
            LOG_ERROR("recv failed1");
            ret = SOCKET_ERROR;
        }
        else if (s->response.magic != CRYPTO_MAGIC_RES)
        {
            LOG_ERROR("Invalid response magic");
            ret = PROTOCOL_ERROR;
        }
        else if (s->response.status != 0)
        {
            LOG_ERROR("Invalid response status: %d", s->response.status);
            ret = RESPONSE_ERROR;
        }
        else
        {
            ret = OK;
        }
    }
    return ret;
}

cc_status_t cc_send_request(crypto_session_t *s, const void *payload, uint32_t payload_len)
{
    LOG_ENTRY("s=%p, fd=%d, op_type=%d, op_step=%d, payload_len=%u",
              s, s->fd, s->request.op_type, s->request.op_step, payload_len);

    s->request.payload_len = payload_len;

    // Send Header
    if (send(s->fd, &s->request, sizeof(struct crypto_msg_header), 0) != sizeof(struct crypto_msg_header))
    {
        LOG_ERROR("send header");
        return SOCKET_ERROR;
    }

    // Send Payload if exists
    if (payload && s->request.payload_len > 0)
    {
        if (send(s->fd, payload, payload_len, 0) != payload_len)
        {
            LOG_ERROR("send payload");
            return SOCKET_ERROR;
        }
    }

    return OK;
}

void *cc_connect()
{
    // LOG_ENTRY("s=%p", s);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG_ERROR("socket, fd=%d", fd);
        return NULL;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, CRYPTOD_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        LOG_ERROR("connect, fd=%d, ret=%d", fd, ret);
        close(fd);
        return NULL;
    }

    crypto_session_t *s = (crypto_session_t *)malloc(sizeof(crypto_session_t));
    if (!s)
    {
        LOG_ERROR("malloc, fd=%d", fd);
        close(fd);
    }
    memset(s, 0, sizeof(crypto_session_t));
    s->fd = fd;
    LOG_EXIT("s=%p, fd=%d", s, s->fd);
    return s;
}

void cc_disconnect(void *context)
{
    crypto_session_t *s = (crypto_session_t *)context;
    LOG_ENTRY("s=%p, fd=%d", s, s->fd);
    if (s->fd >= 0)
    {
        close(s->fd);
    }
    s->fd = -1;
    free(s);
}

cc_status_t cc_check_received_error(crypto_session_t *s)
{
    cc_status_t ret = cc_read_response(s, 0);
    if (ret != TIMEOUT)
    {
        LOG_ERROR("received unexpected data, closing connection");
        // cc_disconnect(s);
        ret = UNEXPECTED_DATA;
    }
    return ret;
}

cc_status_t cc_send_init(crypto_session_t *s, crypto_op_type_t op_type, const void *payload, uint32_t payload_len)
{
    cc_status_t ret = cc_check_received_error(s);
    if (ret == TIMEOUT)
    {
        s->request.magic = CRYPTO_MAGIC_REQ;
        s->request.version = CRYPTO_PROTO_VERSION;
        s->request.op_type = op_type;
        s->request.op_step = STEP_INIT;

        ret = cc_send_request(s, payload, payload_len);
    }
    return ret;
}

int cc_hmac_init(void *context, crypto_key_id_t key_id, crypto_hash_alg_t hash_alg)
{
    crypto_session_t *s = (crypto_session_t *)context;
    LOG_ENTRY("s=%p, fd=%d, key_id=%d, hash_alg=%d", s, s->fd, key_id, hash_alg);
    struct hmac_params params = {.key_id = key_id, .hash_alg = hash_alg};
    cc_status_t ret = cc_send_init(s, OP_TYPE_HMAC, &params, sizeof(params));
    return ret == OK ? 1 : 0;
}

int cc_hmac_update(void *context, const uint8_t *data, uint32_t len)
{
    crypto_session_t *s = (crypto_session_t *)context;
    LOG_ENTRY("s=%p, fd=%d, len=%u", s, s->fd, len);
    cc_status_t ret = cc_check_received_error(s);
    if (ret == TIMEOUT)
    {
        s->request.op_step = STEP_UPDATE;
        ret = cc_send_request(s, data, len);
    }
    return ret == OK ? 1 : 0;
}

int cc_hmac_final(void *context, uint8_t *out, uint32_t *out_len)
{
    crypto_session_t *s = (crypto_session_t *)context;
    LOG_ENTRY("socket=%d, out_len=%u", s->fd, *len);
    cc_status_t ret = cc_check_received_error(s);
    if (ret == TIMEOUT)
    {
        uint32_t buf_len = *out_len;
        *out_len = 0;
        s->request.op_step = STEP_FINISH;
        ret = cc_send_request(s, NULL, 0U);
        if (ret != OK)
        {
            LOG_ERROR("failed to send finish");
            // cc_disconnect(s);
            return 0;
        }

        ret = cc_read_response(s, 10000);
        if (ret != OK)
        {
            LOG_ERROR("failed to read response for finish");
            // cc_disconnect(s);
            return 0;
        }

        uint32_t payload_len = s->response.payload_len;

        LOG_DEBUG("status: %u, payload_len=%u", s->response.status, payload_len);

        if (buf_len < payload_len)
        {
            LOG_ERROR("buffer %u < payload %u", buf_len, payload_len);
            // cc_disconnect(s);
            return 0;
        }

        if (payload_len > 0)
        {
            if (recv(s->fd, out, payload_len, MSG_WAITALL) != payload_len)
            {
                LOG_ERROR("recv failed2");
                return 0;
            }
            *out_len = payload_len;
        }
    }
    return 1;
}
