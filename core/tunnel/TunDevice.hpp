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
#include <cstddef>
#include <unistd.h>


class TunException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class TunDevice final {
public:
    static constexpr size_t BUFFER_SIZE = 2048;

    explicit TunDevice(const std::string& dev_name);
    ~TunDevice();
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;
    TunDevice(TunDevice&& other) noexcept;
    TunDevice& operator=(TunDevice&& other) noexcept;

    void up(const std::string& ip_addr, const std::string& mask) const;
    void write_packet(std::span<const std::byte> packet) const;

    [[nodiscard]] int get_fd() const noexcept { return _fd; }
    [[nodiscard]] const std::string& get_name() const noexcept { return _name; }
    template <typename Handler>
       void read_all_packets(Handler&& handler) const {
        while (true) {
            std::byte stack_buffer[BUFFER_SIZE];
            const ssize_t nread = read(_fd, stack_buffer, sizeof(stack_buffer));
            if (nread > 0) {
                handler(std::span<const std::byte>(stack_buffer, static_cast<size_t>(nread)));
                continue;
            }

            if (nread == -1) {
                const int err = errno;
                if (err == EAGAIN || err == EWOULDBLOCK) break;
                if (err == EINTR) continue;
                throw std::system_error(err, std::system_category(), "TUN read error");
            }
            break;
        }
    }
private:
    int _fd{-1};
    std::string _name;
};