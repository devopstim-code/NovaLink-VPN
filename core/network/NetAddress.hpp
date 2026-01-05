#pragma once
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <stdexcept>

struct NetAddress {
    sockaddr_storage storage{};
    socklen_t len{sizeof(sockaddr_storage)};

    NetAddress() {
        std::memset(&storage, 0, sizeof(storage));
    }

    // explicit to avoid accidental type casts
    explicit NetAddress(const std::string& ip, uint16_t port) {
        std::memset(&storage, 0, sizeof(storage));

        if (inet_pton(AF_INET, ip.c_str(), &get_sin()->sin_addr) > 0) {
            get_sin()->sin_family = AF_INET;
            get_sin()->sin_port = htons(port);
            len = sizeof(sockaddr_in);
        } else if (inet_pton(AF_INET6, ip.c_str(), &get_sin6()->sin6_addr) > 0) {
            get_sin6()->sin6_family = AF_INET6;
            get_sin6()->sin6_port = htons(port);
            len = sizeof(sockaddr_in6);
        } else {
            throw std::runtime_error("Invalid IP format (DNS resolution not implemented yet): " + ip);
        }
    }

    sockaddr_in* get_sin() { return reinterpret_cast<sockaddr_in*>(&storage); }
    const sockaddr_in* get_sin() const { return reinterpret_cast<const sockaddr_in*>(&storage); }
    sockaddr_in6* get_sin6() { return reinterpret_cast<sockaddr_in6*>(&storage); }
    const sockaddr_in6* get_sin6() const { return reinterpret_cast<const sockaddr_in6*>(&storage); }

    uint16_t get_port() const {
        if (storage.ss_family == AF_INET) return ntohs(get_sin()->sin_port);
        return ntohs(get_sin6()->sin6_port);
    }
};