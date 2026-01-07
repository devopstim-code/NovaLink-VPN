#include "UdpSocket.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <system_error>

UdpSocket::UdpSocket(int family)
    : _fd(socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) {
    if (_fd == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to create UDP socket");
    }
}

UdpSocket::~UdpSocket() {
    if (_fd != -1) {
        close(_fd);
    }
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : _fd(other._fd) {
    other._fd = -1;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        if (_fd != -1) {
            close(_fd);
        }
        _fd = other._fd;
        other._fd = -1;
    }
    return *this;
}

void UdpSocket::bind(uint16_t port, bool ipv6) {
    NetAddress addr(ipv6 ? "::" : "0.0.0.0", port);

    const auto* addr_ptr = static_cast<const struct sockaddr*>(
        static_cast<const void*>(&addr.storage)
    );

    if (::bind(_fd, addr_ptr, addr.len) == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to bind UDP socket");
    }
}

ssize_t UdpSocket::send(std::span<const std::byte> data, const NetAddress& dest) const {
    const auto* addr_ptr = static_cast<const struct sockaddr*>(
        static_cast<const void*>(&dest.storage)
    );

    return sendto(_fd, data.data(), data.size(), 0, addr_ptr, dest.len);
}

ssize_t UdpSocket::receive(std::span<std::byte> buf, NetAddress& out_addr) const {
    auto* addr_ptr = static_cast<struct sockaddr*>(
        static_cast<void*>(&out_addr.storage)
    );
    out_addr.len = sizeof(out_addr.storage);

    return recvfrom(_fd, buf.data(), buf.size(), 0, addr_ptr, &out_addr.len);
}