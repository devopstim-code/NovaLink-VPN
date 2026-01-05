/*****************************************************************//**
* \file   TunDevice.cpp
 * \brief  Краткое описание модуля NovaLink Vpn
 * * \author Devopstim
 * \date   2025-2026
 * \project NovaLink Vpn
 * * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/

#include "TunDevice.hpp"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>
#include <cstdlib>

TunDevice::TunDevice(const std::string& dev_name) : _fd(-1) {
    _fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (_fd == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to open /dev/net/tun");
    }

    struct ifreq ifr{};
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (!dev_name.empty()) {
        std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);
    }

    if (ioctl(_fd, TUNSETIFF, reinterpret_cast<void*>(&ifr)) == -1) {
        int err = errno;
        close(_fd);
        throw std::system_error(err, std::system_category(), "ioctl TUNSETIFF failed");
    }

    _name = ifr.ifr_name;
}

TunDevice::~TunDevice() {
    if (_fd != -1) close(_fd);
}

TunDevice::TunDevice(TunDevice&& other) noexcept
    : _fd(other._fd), _name(std::move(other._name)) {
    other._fd = -1;
}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
    if (this != &other) {
        if (_fd != -1) close(_fd);
        _fd = other._fd;
        _name = std::move(other._name);
        other._fd = -1;
    }
    return *this;
}

void TunDevice::up(const std::string& ip_addr, const std::string& mask) {
    std::string cmd_addr = "ip addr add " + ip_addr + "/" + mask + " dev " + _name;
    std::string cmd_link = "ip link set dev " + _name + " up";

    if (std::system(cmd_addr.c_str()) != 0)
        throw std::runtime_error("Failed to set IP address");
    if (std::system(cmd_link.c_str()) != 0)
        throw std::runtime_error("Failed to set link UP");
}

void TunDevice::write_packet(std::span<const uint8_t> packet) {
    if (write(_fd, packet.data(), packet.size()) == -1) {
        if (errno != EAGAIN && errno != EINTR) {
            throw std::system_error(errno, std::system_category(), "TUN write error");
        }
    }
}