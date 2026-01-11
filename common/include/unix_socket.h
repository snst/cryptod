// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/ioctl.h>
#include "crypto_exception.h"
#include "log_macro.h"

class UnixSocket
{
protected:
    int fd_;

public:
    UnixSocket(int fd) : fd_(fd)
    {
    }
    UnixSocket()
    {
        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0)
        {
            throw CryptoException(crypto_code_t::COM_ERROR, "Failed to create socket");
        }
    }
    ~UnixSocket()
    {
        disconnect();
    }

    void disconnect()
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
            throw CryptoException(crypto_code_t::COM_ERROR, "Failed to connect socket, ret=" + std::to_string(ret));
        }
    }

    void setRecvTimeout(uint32_t sec, uint32_t ms)
    {
        struct timeval tv;
        tv.tv_sec = sec;
        tv.tv_usec = ms * 1000U;

        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    }

    bool recv(void *data, size_t *len)
    {
        ssize_t ret = ::recv(fd_, data, *len, 0);
        if (ret > 0)
        {
            *len = ret;
            return true;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return false;
        }

        throw CryptoException(crypto_code_t::COM_ERROR, "Socket recv error, ret=" + std::to_string(ret));
    }

    bool recvComplete(void *data, size_t len, int32_t timeout = -1)
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
            throw CryptoException(crypto_code_t::COM_ERROR, "Socket recv error, len=" + std::to_string(len) + ", ret=" + std::to_string(ret));

        return true;
    }

    void send(const void *data, size_t len)
    {
        ssize_t ret = ::send(fd_, data, len, 0);
        if (ret != len)
            throw CryptoException(crypto_code_t::COM_ERROR, "Socket send error, len=" + std::to_string(len) + ", ret=" + std::to_string(ret));
    }

    uint32_t readable_bytes(int32_t timeout)
    {
        if (fd_ < 0)
            throw CryptoException(crypto_code_t::COM_ERROR, "readable_bytes failed, invalid socket");

        // Step 1: Poll to check if fd is readable or closed
        struct pollfd pfd = {0};
        pfd.fd = fd_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, timeout); // timeout=0 -> non-blocking
        if (ret < 0)
            throw CryptoException(crypto_code_t::COM_ERROR, "socket poll failed");

        if (ret == 0)
        {
            // LOG_EXIT("No data, timeout=%d", timeout);
            return 0;
        }

        // Check for errors / hangup
        if (pfd.revents & (POLLERR | POLLHUP))
        {
            //    return 0; // EOF or error, nothing to read
            throw CryptoException(crypto_code_t::COM_ERROR, "socket closed");
        }

        // Step 2: Query exact number of bytes available
        int bytes_available = 0;
        if (ioctl(fd_, FIONREAD, &bytes_available) < 0)
        {
            throw CryptoException(crypto_code_t::COM_ERROR, "socket ioctl failed");
        }

        return bytes_available;
    }

    int fd()
    {
        return fd_;
    }

    bool getCred(struct ucred &cred)
    {
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(fd_, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == -1)
        {
            LOG_ERROR("getsockopt, failed to get uid.. fd=%d", fd_);
            return false;
        }
        else
        {
            return true;
        }
    }
};