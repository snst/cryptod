
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <iostream>
#include <unistd.h>
#include <unordered_map>

#include "ikeystore.h"
#include "crypto_service_base.h"
#include "icrypto_backend.h"
#include "crypto_socket_hdr.h"
#include "unix_socket.h"

class Connection;

typedef enum
{
    WAIT_HDR = 0,
    WAIT_PAYLOAD = 1,

} connection_state_t;

struct Session
{
    Connection *conn_;
    uint32_t session_id_;
    crypto_msg_header_t request_;
    std::unique_ptr<ICryptoOperation> operation_;
    Session(Connection *conn, uint32_t session_id) : conn_(conn), session_id_(session_id) {};
    void send(const void *data, uint32_t len);
};

class Connection
{
public:
    Connection(int fd) : socket_(fd), state_(WAIT_HDR) {}
    bool updateCred();
    bool responseReady();
    UnixSocket socket_;
    struct ucred cred_;
    std::string label;
    crypto_msg_header_t request_;
    connection_state_t state_;
    std::unordered_map<uint32_t, std::unique_ptr<Session>> sessions_;

    Session *getSession(uint32_t session_id)
    {
        auto it = sessions_.find(session_id);
        if (it == sessions_.end())
        {
            return NULL;
        }
        return (it->second).get();
    }

    Session *addSession(uint32_t session_id)
    {
        if (getSession(session_id) != NULL)
        {
            LOG_ERROR("Session already existing: %u", session_id);
            return NULL;
        }
        auto session = std::make_unique<Session>(this, session_id);
        Session *s1 = session.get();
        sessions_[session_id] = std::move(session);
        // Session* s2 = getSession(session_id);
        return s1;
    }

    void removeSession(uint32_t session_id)
    {
        auto it = sessions_.find(session_id);
        if (it != sessions_.end())
        {
            sessions_.erase(it);
        }
    }
};

class SocketCryptoService final : public CryptoServiceBase
{
public:
    SocketCryptoService(ICryptoBackend &crypto_backend, IKeyStore &keystore);
    ~SocketCryptoService();
    int32_t run(std::string path);

protected:
    int server_fd_;
    std::string socket_path_;
    int epoll_fd_;
    std::unordered_map<int, std::unique_ptr<Connection>> connections_;

    void setupSocket();
    void sendResponseToLastRequest(Session &session, crypto_code_t status, const void *payload = NULL, uint32_t payload_len = 0U);
    void mainServerLoop();
    bool processConnection(Connection &connection);
    void handleReceivedPacket(Connection &conn, crypto_msg_header_t &request, uint8_t *payload, const size_t payload_len);
    void handleHmacRequest(Connection &conn, crypto_msg_header_t &request, uint8_t *payload, const size_t payload_len);

    bool epoll_ctl_add(int fd, struct epoll_event *ev);
    void epoll_ctl_del(int fd);
};
