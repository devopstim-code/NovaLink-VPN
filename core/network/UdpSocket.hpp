/*****************************************************************//**
* \file   UdpSocket.hpp
* \brief  A wrapper around system UDP sockets.
* * Provides an interface for creating, binding, and exchanging encrypted datagrams between a client and server.
* * \author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/
#pragma once

#include "NetAddress.hpp"
#include <span>
#include <system_error>

class UdpSocket {
public:
    // Buffer support up to 2KB (enough for standard MTU 1500 + headers)
    static constexpr size_t MAX_PACKET_SIZE = 2048;

    explicit UdpSocket(int family = AF_INET);
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    void bind(uint16_t port, bool ipv6 = false);

    // Return ssize_t to understand the size of the transferred data
    ssize_t send(std::span<const uint8_t> data, const NetAddress& target);
    ssize_t receive(std::span<uint8_t> buffer, NetAddress& out_sender);

    int get_fd() const noexcept { return _fd; }

private:
    int _fd{-1};
    void set_nonblocking();
};