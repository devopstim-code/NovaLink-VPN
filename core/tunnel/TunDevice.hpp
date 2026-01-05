/*****************************************************************//**
* \file  TunDevice.hpp
* \brief  Tunnel Network Interface (TUN) Management.
* * Responsible for creating a Layer 3 interface in Linux, configuring its IP address
* and reading/writing raw IP packets from the system kernel.
* * \author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/
#pragma once

#include <string>
#include <system_error>
#include <span>
#include <cstdint>
#include <unistd.h>

class TunDevice {
public:
    static constexpr size_t BUFFER_SIZE = 2048;

    explicit TunDevice(const std::string& dev_name);
    ~TunDevice();

    // Copying prohibited
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    // Moving
    TunDevice(TunDevice&& other) noexcept;
    TunDevice& operator=(TunDevice&& other) noexcept;

    // Interface customization
    void up(const std::string& ip_addr, const std::string& mask);
    void write_packet(std::span<const uint8_t> packet);

    int get_fd() const noexcept { return _fd; }
    const std::string& get_name() const noexcept { return _name; }

    template <typename Handler>
    void read_all_packets(Handler&& handler) {
        while (true) {
            ssize_t nread = read(_fd, _buffer, sizeof(_buffer));
            if (nread > 0) {
                handler(std::span<const uint8_t>(_buffer, static_cast<size_t>(nread)));
            } else if (nread == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                throw std::system_error(errno, std::system_category(), "TUN read error");
            } else break;
        }
    }

private:
    int _fd;
    std::string _name;
    uint8_t _buffer[BUFFER_SIZE];
};