/*****************************************************************//**
* \file  EpollEngine.hpp
* \brief Asynchronous event dispatcher.
* * Uses the epoll system call to simultaneously monitor
* activity on the TUN interface and network socket without blocking the thread.
* * \author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/
#pragma once

#include <sys/epoll.h>
#include <vector>
#include <atomic>
#include <system_error>


struct EventContext {
    int fd;
    void* owner;
    uint32_t last_events;
};

class EpollEngine {
public:

    static constexpr int DEFAULT_MAX_EVENTS = 128;

    EpollEngine();
    ~EpollEngine();

    EpollEngine(const EpollEngine&) = delete;
    EpollEngine& operator=(const EpollEngine&) = delete;

    EpollEngine(EpollEngine&& other) noexcept;
    EpollEngine& operator=(EpollEngine&& other) noexcept;

    static void set_nonblocking(int fd);

    void add(int fd, uint32_t events, EventContext* ctx);
    void modify(int fd, uint32_t events, EventContext* ctx);
    void remove(int fd);

    int wait(std::vector<epoll_event>& event_buffer, int timeout_ms = -1);

    void stop() noexcept { _running.store(false); }
    bool is_running() const noexcept { return _running.load(); }

private:
    int _epoll_fd = -1;
    std::atomic<bool> _running{true};

    void control(int op, int fd, uint32_t events, EventContext* ctx);
};