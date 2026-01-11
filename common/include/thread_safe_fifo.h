// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#include <deque>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <algorithm>
#include <cstdint>

class ThreadSafeFifo
{
private:
    std::deque<uint8_t> m_buffer;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;

public:
    ThreadSafeFifo() = default;

    void write(const uint8_t *data, size_t len)
    {
        if (!data || len == 0)
            return;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_buffer.insert(m_buffer.end(), data, data + len);
        }
        // notify_all() is called after releasing the lock or at the end of scope
        // This wakes up the blocked reader thread
        m_cv.notify_all();
    }

    bool dequeue(void *out_buffer, size_t len)
    {
        if (m_buffer.size() >= len)
        {
            std::copy(m_buffer.begin(), m_buffer.begin() + len, (uint8_t *)out_buffer);
            m_buffer.erase(m_buffer.begin(), m_buffer.begin() + len);
            return true;
        }
        return false;
    }

    bool recvComplete(void *out_buffer, size_t len, int32_t timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (dequeue(out_buffer, len))
            return true;

        while (timeout == -1)
        {
            m_cv.wait(lock);
            if (dequeue(out_buffer, len))
                return true;
        }

        if (timeout > 0)
        {
            m_cv.wait_for(lock, std::chrono::milliseconds(timeout));
            if (dequeue(out_buffer, len))
                return true;
        }

        return false;
    }

    size_t available() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_buffer.size();
    }
};
