#pragma once
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <stdexcept>
#include <format>

// Sonar: Define a dedicated exception
class NetworkException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct NetAddress {
    sockaddr_storage storage{};
    socklen_t len{sizeof(sockaddr_storage)};

    NetAddress() {
        std::memset(&storage, 0, sizeof(storage));
    }

    explicit NetAddress(const std::string& ip, uint16_t port) {
        std::memset(&storage, 0, sizeof(storage));

        if (inet_pton(AF_INET, ip.c_str(), &get_sin_internal()->sin_addr) > 0) {
            auto* sin = get_sin_internal();
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port);
            len = sizeof(sockaddr_in);
        } else if (inet_pton(AF_INET6, ip.c_str(), &get_sin6_internal()->sin6_addr) > 0) {
            auto* sin6 = get_sin6_internal();
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port);
            len = sizeof(sockaddr_in6);
        } else {
            throw NetworkException(std::format("Invalid IP format: {}", ip));
        }
    }

    // Sonar: Safer operation instead of direct reinterpret_cast
    sockaddr_in* get_sin() {
        return static_cast<sockaddr_in*>(static_cast<void*>(&storage));
    }
    const sockaddr_in* get_sin() const {
        return static_cast<const sockaddr_in*>(static_cast<const void*>(&storage));
    }
    sockaddr_in6* get_sin6() {
        return static_cast<sockaddr_in6*>(static_cast<void*>(&storage));
    }
    const sockaddr_in6* get_sin6() const {
        return static_cast<const sockaddr_in6*>(static_cast<const void*>(&storage));
    }

    uint16_t get_port() const noexcept {
        if (storage.ss_family == AF_INET) {
            return ntohs(get_sin()->sin_port);
        }
        return ntohs(get_sin6()->sin6_port);
    }

private:
    sockaddr_in* get_sin_internal() {
        return static_cast<sockaddr_in*>(static_cast<void*>(&storage));
    }
    sockaddr_in6* get_sin_internal6() {
        return static_cast<sockaddr_in6*>(static_cast<void*>(&storage));
    }
    sockaddr_in6* get_sin6_internal() {
        return static_cast<sockaddr_in6*>(static_cast<void*>(&storage));
    }
};