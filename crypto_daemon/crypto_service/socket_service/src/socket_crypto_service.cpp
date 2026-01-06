
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

void Session::send(const void *data, uint32_t len)
{
    conn_->socket_.send(data, len);
}

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
        throw CryptoException(crypto_code_t::COM_ERROR, "Failed to create daemon socket.");

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    unlink(socket_path_.c_str());
    if (bind(server_fd_, (sockaddr *)&addr, sizeof(addr)) == -1)
        throw CryptoException(crypto_code_t::COM_ERROR, "Failed to bind daemon socket.");

    if (listen(server_fd_, 5) == -1)
        throw CryptoException(crypto_code_t::COM_ERROR, "Failed to listen daemon socket.");
}

void SocketCryptoService::sendResponseToLastRequest(Session &session, crypto_code_t status, const void *payload, uint32_t payload_len)
{
    crypto_msg_header response = session.request_;
    response.magic = CRYPTO_MAGIC_RES;
    response.status = (uint32_t)status;
    response.payload_len = payload_len;
    session.send(&response, sizeof(response));

    if (payload != NULL && payload_len > 0)
    {
        session.send(payload, payload_len);
    }
}

void SocketCryptoService::mainServerLoop()
{
    LOG_ENTRY("");
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ == -1)
        throw CryptoException(crypto_code_t::COM_ERROR, "Failed to epoll_create1.");

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = server_fd_;
    if (!epoll_ctl_add(server_fd_, &ev))
        throw CryptoException(crypto_code_t::COM_ERROR, "Failed to epoll_ctl_add.");

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
                auto conn = std::make_unique<Connection>(client_fd);

                epoll_event client_ev{};
                client_ev.events = EPOLLIN | EPOLLET; // Edge-triggered
                client_ev.data.fd = client_fd;
                if (epoll_ctl_add(client_fd, &client_ev) && conn->updateCred())
                {
                    LOG_INFO("Adding connection: %s", conn->label.c_str());
                    connections_[client_fd] = std::move(conn);
                }
            }
            else
            {
                int client_fd = events[i].data.fd;
                auto it = connections_.find(client_fd);
                if (it == connections_.end())
                {
                    // Unknown fd, remove from epoll to be safe
                    LOG_ERROR("No connection for fd=%d found. Closing socket.", client_fd);
                    epoll_ctl_del(client_fd);
                    close(client_fd);
                    continue;
                }

                Connection &conn = *it->second;

                if (!processConnection(conn))
                {
                    LOG_INFO("Removing connection: %s", conn.label.c_str());
                    epoll_ctl_del(conn.socket_.fd());
                    connections_.erase(it);
                }
            }
        }
    }
}

void SocketCryptoService::handleHmacRequest(Connection &conn, crypto_msg_header &request, uint8_t *payload, const size_t payload_len)
{
    Session *session = NULL;
    if (request.op_step == STEP_INIT)
    {
        session = conn.addSession(request.session_id);
    }
    else
    {
        session = conn.getSession(request.session_id);
    }
    if (!session)
    {
        LOG_ERROR("Failed to create HMAC session");
        return;
    }

    session->request_ = request;

    switch (request.op_step)
    {
    case STEP_INIT:
    {
        if (payload_len != sizeof(struct hmac_params))
        {
            LOG_ERROR("payload_len != sizeof(struct hmac_params)");
        }
        else
        {
            struct hmac_params *hmac = (struct hmac_params *)payload;
            LOG_DEBUG("OP_TYPE_HMAC:STEP_INIT: key=%u, alg=%u", hmac->key_id, hmac->hash_alg);
            auto key_res = keystore_.getKey(hmac->key_id);
            if (key_res.ok())
            {
                session->operation_ = crypto_backend_.createHMAC((crypto_hash_alg_t)hmac->hash_alg, key_res.data);
                session->operation_->init();
            }
            else
            {
                // ret = MSG_KEY_NOT_FOUND;
                LOG_INFO("KeyId not found: 0x%x (%u)", hmac->key_id, hmac->key_id);
                sendResponseToLastRequest(*session, crypto_code_t::KEY_NOT_FOUND);
                conn.removeSession(session->session_id_);
            }
        }
    }
    break;
    case STEP_UPDATE:
    {
        LOG_DEBUG("OP_TYPE_HMAC:STEP_UPDATE: len=%u", session.request.payload_len);
        session->operation_->update((const uint8_t *)payload, session->request_.payload_len);
    }
    break;
    case STEP_FINISH:
    {
        LOG_DEBUG("OP_TYPE_HMAC:STEP_FINISH: len=%u", session.request.payload_len);
        auto hmac = session->operation_->finish();
        sendResponseToLastRequest(*session, crypto_code_t::OK, hmac.data(), hmac.size());
        conn.removeSession(session->session_id_);
    }
    break;
    default:
        break;
    }
}

void SocketCryptoService::handleReceivedPacket(Connection &conn, crypto_msg_header &request, uint8_t *payload, size_t const payload_len)
{
    switch (request.op_type)
    {
    case OP_TYPE_HMAC:
        handleHmacRequest(conn, request, payload, payload_len);
        break;
    default:
        break;
    }
}

bool SocketCryptoService::processConnection(Connection &conn)
{
    try
    {
        bool has_data = true;
        while (has_data)
        {
            if (conn.state_ == WAIT_HDR)
            {
                has_data = conn.socket_.recv(&conn.request_, sizeof(conn.request_), 0);
                if (has_data)
                {
                    LOG_DEBUG("recv msg: %s", dump_crypto_msg(&conn.request_));
                    if (!valid_crypto_msg_req(&conn.request_))
                    {
                        LOG_ERROR("Received invalid crypto_msg_header. Closing connection.");
                        return false;
                    }
                    if (conn.request_.payload_len > 0)
                    {
                        conn.state_ = WAIT_PAYLOAD;
                    }
                    else
                    {
                        handleReceivedPacket(conn, conn.request_, NULL, 0);
                    }
                }
            }

            if (conn.state_ == WAIT_PAYLOAD)
            {
                std::vector<uint8_t> buffer(2048);
                has_data = conn.socket_.recv(buffer.data(), conn.request_.payload_len, 0);
                if (has_data)
                {
                    LOG_DEBUG("Read complete payload %u", conn.request_.payload_len);
                    handleReceivedPacket(conn, conn.request_, buffer.data(), conn.request_.payload_len);
                    conn.state_ = WAIT_HDR;
                }
                else
                {

                    LOG_DEBUG("Wait for complete payload %u", conn.request_.payload_len);
                }
            }
        }

        return true;
    }
    catch (const CryptoException &e)
    {
        return false;
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

bool Connection::updateCred()
{
    label = "fd=" + std::to_string(socket_.fd());
    if (socket_.getCred(cred_))
    {
        label += " pid=" + std::to_string(cred_.pid) + " uid=" + std::to_string(cred_.uid) + " gid=" + std::to_string(cred_.gid);
        return true;
    }
    return false;
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
    mainServerLoop();
    return 0;
}