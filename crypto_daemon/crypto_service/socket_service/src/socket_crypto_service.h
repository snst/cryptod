
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <iostream>
#include <unistd.h>
#include <unordered_map>

#include "ikeystore.h"
#include "icrypto_service.h"
#include "icrypto_backend.h"
#include "crypto_socket_hdr.h"

typedef enum
{
    MSG_OK_CONTINUE = 0,
    MSG_OK_CLOSE = 1,
    MSG_INCOMPLETE_HDR = 2,
    SEND_ERROR = 3,
    MSG_INVALID_MAGIC = 4,
    MSG_INCOMPLETE_PAYLOAD = 5,
    MSG_INVALID_CMD = 6,
    MSG_KEY_NOT_FOUND = 7
} request_result_t;

struct Session
{
    int fd;
    std::vector<char> inbuf;
    uid_t uid{0};
    gid_t gid{0};
    pid_t pid{0};
    std::string label;
    std::unique_ptr<ICryptoOperation> operation;
    crypto_msg_header request;

    Session(int fd_ = -1);
    ~Session();
    bool updateCred();
    void close();
    ssize_t readData();
    bool hasData();
    request_result_t checkPacket();
};

class SocketCryptoService final : public ICryptoService
{
public:
    SocketCryptoService() = default;
    ~SocketCryptoService();
    int32_t run(ICryptoBackend *crypto_backend, IKeyStore *keystore, const char *path);

protected:
    int server_fd_;
    std::string socket_path_;
    int epoll_fd_;
    std::unordered_map<int, std::unique_ptr<Session>> sessions_;
    ICryptoBackend *crypto_backend_;
    IKeyStore *keystore_;

    void setupSocket();
    bool sendResponse(Session &session, const void *payload, uint32_t payload_len);
    bool sendResponseToLastRequest(Session &session, int32_t status, const void *payload, uint32_t payload_len);
    request_result_t handleRequest(Session &session);
    void loopHandleConnections();
    bool processSessionBufferedData(Session &session);
    bool processSession(Session &session);

    bool epoll_ctl_add(int fd, struct epoll_event *ev);
    void epoll_ctl_del(int fd);
};
