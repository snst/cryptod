// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/ioctl.h>
#include "crypto_exception.h"

class UnixSocket
{
protected:
    int fd_;

public:
    UnixSocket()
    {
        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0)
        {
            throw CryptoException(CryptoException::Reason::Socket, "Failed to create socket");
        }
    }
    ~UnixSocket()
    {
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    void connect(std::string path)
    {
        struct sockaddr_un addr = {.sun_family = AF_UNIX};
        strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        int ret = ::connect(fd_, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0)
        {
            throw CryptoException(CryptoException::Reason::Socket, "Failed to connect socket, ret=" + std::to_string(ret));
        }
    }

    bool recv(void *data, size_t len, int32_t timeout = -1)
    {
        if (timeout != -1)
        {
            uint32_t available = readable_bytes(timeout);
            if (available < len)
            {
                return false;
            }
        }

        ssize_t ret = ::recv(fd_, data, len, MSG_WAITALL);
        if (ret != len)
            throw CryptoException(CryptoException::Reason::Socket, "Socket recv error, len=" + std::to_string(len) + ", ret=" + std::to_string(ret));

        return true;
    }

    void send(const void *data, size_t len)
    {
        ssize_t ret = ::send(fd_, data, len, 0);
        if (ret != len)
            throw CryptoException(CryptoException::Reason::Socket, "Socket send error, len=" + std::to_string(len) + ", ret=" + std::to_string(ret));
    }

    uint32_t readable_bytes(int32_t timeout)
    {
        if (fd_ < 0)
            throw CryptoException(CryptoException::Reason::Socket, "readable_bytes failed, invalid socket");

        // Step 1: Poll to check if fd is readable or closed
        struct pollfd pfd = {0};
        pfd.fd = fd_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, timeout); // timeout=0 -> non-blocking
        if (ret < 0)
            throw CryptoException(CryptoException::Reason::Socket, "socket poll failed");

        if (ret == 0)
        {
            // LOG_EXIT("No data, timeout=%d", timeout);
            return 0;
        }

        // Check for errors / hangup
        /*if (pfd.revents & (POLLERR | POLLHUP))
        {
            return 0; // EOF or error, nothing to read
        }*/

        // Step 2: Query exact number of bytes available
        int bytes_available = 0;
        if (ioctl(fd_, FIONREAD, &bytes_available) < 0)
        {
            throw CryptoException(CryptoException::Reason::Socket, "socket ioctl failed");
        }

        return bytes_available;
    }

    int fd()
    {
        return fd_;
    }
};