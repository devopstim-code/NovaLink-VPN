#include "UdpSocket.hpp"
#include <unistd.h>
#include <sys/socket.h>

UdpSocket::UdpSocket(int family) {
    // We use SOCK_NONBLOCK directly in socket(), if the kernel allows it (Linux can do this)
    _fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (_fd == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to create UDP socket");
    }
}

UdpSocket::~UdpSocket() {
    if (_fd != -1) close(_fd);
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : _fd(other._fd) {
    other._fd = -1;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        if (_fd != -1) close(_fd);
        _fd = other._fd;
        other._fd = -1;
    }
    return *this;
}

void UdpSocket::bind(uint16_t port, bool ipv6) {
    // Use the address "0.0.0.0" or "::" to listen on all interfaces
    NetAddress addr(ipv6 ? "::" : "0.0.0.0", port);
    if (::bind(_fd, reinterpret_cast<const sockaddr*>(&addr.storage), addr.len) == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to bind UDP socket");
    }
}

ssize_t UdpSocket::send(std::span<const uint8_t> data, const NetAddress& target) {
    ssize_t sent = sendto(_fd, data.data(), data.size(), 0,
                          reinterpret_cast<const sockaddr*>(&target.storage), target.len);
    if (sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) return -1;
        throw std::system_error(errno, std::system_category(), "UDP send error");
    }
    return sent;
}

ssize_t UdpSocket::receive(std::span<uint8_t> buffer, NetAddress& out_sender) {
    out_sender.len = sizeof(out_sender.storage);
    ssize_t recvd = recvfrom(_fd, buffer.data(), buffer.size(), 0,
                             reinterpret_cast<sockaddr*>(&out_sender.storage), &out_sender.len);
    if (recvd == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) return -1;
        throw std::system_error(errno, std::system_category(), "UDP recv error");
    }
    return recvd;
}