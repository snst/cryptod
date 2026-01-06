
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "socket_crypto_service.h"
#include "log_macro.h"
#include "crypto_exception.h"

#define MAX_EVENTS 10
#define BUFFER_SIZE 2048

SocketCryptoService::~SocketCryptoService()
{
    if (server_fd_ != -1)
        close(server_fd_);
    unlink(socket_path_.c_str());
}

void SocketCryptoService::setupSocket()
{
    server_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_fd_ == -1)
        throw CryptoException(CryptoException::Reason::Socket, "Failed to create daemon socket.");

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    unlink(socket_path_.c_str());
    if (bind(server_fd_, (sockaddr *)&addr, sizeof(addr)) == -1)
        throw CryptoException(CryptoException::Reason::Socket, "Failed to bind daemon socket.");

    if (listen(server_fd_, 5) == -1)
        throw CryptoException(CryptoException::Reason::Socket, "Failed to listen daemon socket.");
}

bool SocketCryptoService::sendResponse(Session &session, const void *payload, uint32_t payload_len)
{
    if (session.fd == -1)
    {
        LOG_ERROR("s=%p, Invalid fd", &session);
        return false;
    }
    ssize_t ret = send(session.fd, payload, payload_len, 0);
    if (ret != payload_len)
    {
        LOG_ERROR("s=%p, Only sent %ld of %u bytes", &session, ret, payload_len);
        return false;
    }
    return true;
}

bool SocketCryptoService::sendResponseToLastRequest(Session &session, int32_t status, const void *payload, uint32_t payload_len)
{
    crypto_msg_header response = session.request;
    response.magic = CRYPTO_MAGIC_RES;
    response.status = status;
    response.payload_len = payload_len;
    bool ret = sendResponse(session, &response, sizeof(response));
    if (!ret || payload == 0)
    {
        return ret;
    }
    return sendResponse(session, payload, payload_len);
}

request_result_t SocketCryptoService::handleRequest(Session &session)
{
    LOG_ENTRY("s=%p, fd=%d", &session, session.fd);
    request_result_t ret = session.checkPacket();

    if (ret != MSG_OK_CONTINUE)
    {
        return ret;
    }

    memcpy(&session.request, session.inbuf.data(), sizeof(crypto_msg_header));

    size_t request_len = sizeof(crypto_msg_header) + session.request.payload_len;
    void *payload = ((uint8_t *)session.inbuf.data()) + sizeof(crypto_msg_header);

    switch (session.request.op_type)
    {
    case OP_TYPE_HMAC:
    {
        switch (session.request.op_step)
        {
        case STEP_INIT:
        {
            if (session.request.payload_len == sizeof(struct hmac_params))
            {
                struct hmac_params *hmac = (struct hmac_params *)payload;
                LOG_DEBUG("OP_TYPE_HMAC:STEP_INIT: key=%u, alg=%u", hmac->key_id, hmac->hash_alg);
                auto key_res = keystore_.getKey(hmac->key_id);
                if (key_res.ok())
                {
                    session.operation = crypto_backend_.createHMAC((crypto_hash_alg_t)hmac->hash_alg, key_res.data);
                    session.operation->init();
                    ret = MSG_OK_CONTINUE;
                }
                else
                {
                    ret = MSG_KEY_NOT_FOUND;
                    LOG_INFO("KeyId not found: 0x%x (%u)", hmac->key_id, hmac->key_id);
                }
            }
        }
        break;
        case STEP_UPDATE:
        {
            LOG_DEBUG("OP_TYPE_HMAC:STEP_UPDATE: len=%u", session.request.payload_len);
            session.operation->update((const uint8_t *)payload, session.request.payload_len);
            ret = MSG_OK_CONTINUE;
        }
        break;
        case STEP_FINISH:
        {
            LOG_DEBUG("OP_TYPE_HMAC:STEP_FINISH: len=%u", session.request.payload_len);
            auto hmac = session.operation->finish();

            if (sendResponseToLastRequest(session, 0, hmac.data(), hmac.size()))
            {
                ret = MSG_OK_CLOSE;
            }
            else
            {
                ret = SEND_ERROR;
            }
        }
        break;
        default:
            break;
        }
    }
    break;
    default:
        break;
    }

    if ((ret == MSG_OK_CONTINUE) || (ret == MSG_OK_CLOSE))
    {
        session.inbuf.erase(session.inbuf.begin(), session.inbuf.begin() + request_len);
    }

    return ret;
}

void SocketCryptoService::loopHandleConnections()
{
    LOG_ENTRY("");
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ == -1)
        throw CryptoException(CryptoException::Reason::Socket, "Failed to epoll_create1.");

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = server_fd_;
    if (!epoll_ctl_add(server_fd_, &ev))
        throw CryptoException(CryptoException::Reason::Socket, "Failed to epoll_ctl_add.");

    std::vector<epoll_event> events(MAX_EVENTS);

    while (true)
    {
        int n = epoll_wait(epoll_fd_, events.data(), MAX_EVENTS, -1);
        if (n == -1)
        {
            LOG_ERROR("epoll_wait");
            continue;
        }

        for (int i = 0; i < n; i++)
        {
            if (events[i].data.fd == server_fd_)
            {
                sockaddr_un client_addr{};
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept4(server_fd_, (sockaddr *)&client_addr, &client_len, SOCK_NONBLOCK);
                if (client_fd == -1)
                {
                    LOG_ERROR("accept");
                    continue;
                }

                // Create session and get client UID/GID/PID
                auto sess = std::make_unique<Session>(client_fd);

                epoll_event client_ev{};
                client_ev.events = EPOLLIN | EPOLLET; // Edge-triggered
                client_ev.data.fd = sess->fd;
                if (epoll_ctl_add(sess->fd, &client_ev) && sess->updateCred())
                {
                    sessions_[client_fd] = std::move(sess);
                }
            }
            else
            {
                int client_fd = events[i].data.fd;
                auto it = sessions_.find(client_fd);
                if (it == sessions_.end())
                {
                    // Unknown fd, remove from epoll to be safe
                    LOG_ERROR("No session for fd=%d found.", client_fd);
                    epoll_ctl_del(client_fd);
                    close(client_fd);
                    continue;
                }

                Session &session = *it->second;

                if (!processSession(session))
                {
                    epoll_ctl_del(session.fd);
                    sessions_.erase(it);
                }
            }
        }
    }
}

bool SocketCryptoService::processSessionBufferedData(Session &session)
{
    while (session.inbuf.size() > 0U)
    {
        request_result_t ret = handleRequest(session);

        switch (ret)
        {
        case MSG_OK_CONTINUE:
            LOG_DEBUG("Process next buffered message. %s", session.label.c_str());
            break;

        case MSG_OK_CLOSE:
            LOG_DEBUG("Request finished. Closing session. %s", session.label.c_str());
            return false;

        case MSG_INCOMPLETE_HDR:
            LOG_DEBUG("Wait for hdr complete. %s", session.label.c_str());
            return true;
        case MSG_INCOMPLETE_PAYLOAD:
            LOG_DEBUG("Wait for payload complete. %s", session.label.c_str());
            return true;

        case MSG_INVALID_MAGIC:
        case MSG_INVALID_CMD:
        case MSG_KEY_NOT_FOUND:
            LOG_ERROR("Serious error(%d). Closing session. %s", ret, session.label.c_str());
            sendResponseToLastRequest(session, ret, NULL, 0UL);
            return false;

        default:
        case SEND_ERROR:
            LOG_ERROR("Serious error(%d). Closing session: %s", ret, session.label.c_str());
            return false;
        }
    }
    return true;
}

bool SocketCryptoService::processSession(Session &session)
{
    request_result_t ret = MSG_OK_CONTINUE;
    ssize_t count = session.readData();
    if (count > 0)
    {
        processSessionBufferedData(session);
        return true;
    }
    else if (count == 0)
    {
        // peer closed
        LOG_INFO("Client closed: %s", session.label.c_str());
        return false;
    }
    else
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no more data
            LOG_DEBUG("Socket would block. return. %s", session.label.c_str());
            return true;
        }
        else
        {
            LOG_ERROR("Client error, closed: %s", session.label.c_str());
            return false;
        }
    }
}

bool SocketCryptoService::epoll_ctl_add(int fd, struct epoll_event *ev)
{
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, ev) == -1)
    {
        LOG_ERROR("failed, fd=%d", fd);
        return false;
    }
    return true;
}

void SocketCryptoService::epoll_ctl_del(int fd)
{
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
}

bool Session::updateCred()
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

Session::Session(int fd_) : fd(fd_)
{
    LOG_ENTRY("");
}

Session::~Session()
{
    LOG_ENTRY("");
    close();
}

void Session::close()
{
    if (fd >= 0)
    {
        ::close(fd);
        fd = -1;
    }
}

ssize_t Session::readData()
{
    char buffer[BUFFER_SIZE];

    // LOG_ENTRY("fd=%d, len=%lu", fd, sizeof(buffer));
    if (fd < 0)
    {
        return -1;
    }

    ssize_t ret = ::read(fd, buffer, sizeof(buffer));
    if (ret > 0)
    {
        inbuf.insert(inbuf.end(), buffer, buffer + ret);
    }
    LOG_EXIT("fd=%d, ret=%ld", fd, ret);
    return ret;
}

bool Session::hasData()
{
    return inbuf.size() > 0UL;
}

request_result_t Session::checkPacket()
{
    LOG_ENTRY("session=%p, fd=%d", this, fd);
    struct crypto_msg_header *hdr = (crypto_msg_header *)inbuf.data();

    if ((inbuf.size() >= sizeof(crypto_msg_header::magic)) && (hdr->magic != CRYPTO_MAGIC_REQ))
    {
        LOG_ERROR(" Invalid packet magic");
        return MSG_INVALID_MAGIC;
    }

    if (inbuf.size() < sizeof(crypto_msg_header))
    {
        LOG_DEBUG(" Header not yet complete. recv size: %lu < %lu.", inbuf.size(), sizeof(crypto_msg_header));
        return MSG_INCOMPLETE_HDR;
    }

    size_t request_len = sizeof(crypto_msg_header) + hdr->payload_len;
    void *payload = ((uint8_t *)hdr) + sizeof(*hdr);

    if (inbuf.size() < request_len)
    {
        LOG_DEBUG(" payload not yet complete. recv size: %lu < %lu", inbuf.size(), request_len);
        return MSG_INCOMPLETE_PAYLOAD;
    }

    return MSG_OK_CONTINUE;
}

SocketCryptoService::SocketCryptoService(ICryptoBackend &crypto_backend, IKeyStore &keystore)
    : CryptoServiceBase(crypto_backend, keystore)
{
}

int32_t SocketCryptoService::run(std::string path)
{
    socket_path_ = path;
    LOG_INFO("Crypto Daemon using unix socket, listening on %s...", path.c_str());

    setupSocket();
    loopHandleConnections();
    return 0;
}