/*****************************************************************//**
* \file  NetAddress.hpp
* \brief Network endpoint abstraction.
* * Provides a high-level wrapper around POSIX 'sockaddr_storage'.
* Handles IPv4/IPv6 transparency, DNS resolution, and address comparison
* logic for the NovaLink routing engine.
**\author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/
#pragma once
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <stdexcept>
#include <format>
#include <functional>

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

    [[nodiscard]] std::string to_string() const {
        std::string ip_str(INET6_ADDRSTRLEN, '\0');

        if (storage.ss_family == AF_INET) {
            inet_ntop(AF_INET, &get_sin()->sin_addr, ip_str.data(), INET_ADDRSTRLEN);
        } else if (storage.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &get_sin6()->sin6_addr, ip_str.data(), INET6_ADDRSTRLEN);
        } else {
            return "unknown";
        }

        ip_str.resize(std::strlen(ip_str.c_str()));
        return std::format("{}:{}", ip_str, get_port());
    }

    bool operator==(const NetAddress& other) const noexcept {
        if (get_port() != other.get_port()) return false;
        return is_same_ip(other);
    }

    [[nodiscard]] bool is_same_ip(const NetAddress& other) const noexcept {
        if (storage.ss_family != other.storage.ss_family) {
            auto check_mapped = [](const sockaddr_in6* a6, const sockaddr_in* a4) {
                const uint8_t* addr6 = a6->sin6_addr.s6_addr;
                bool is_mapped = (std::memcmp(addr6, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12) == 0);
                return is_mapped && (std::memcmp(addr6 + 12, &a4->sin_addr.s_addr, 4) == 0);
            };

            if (storage.ss_family == AF_INET6 && other.storage.ss_family == AF_INET) return check_mapped(get_sin6(), other.get_sin());
            if (storage.ss_family == AF_INET && other.storage.ss_family == AF_INET6) return check_mapped(other.get_sin6(), get_sin());

            return false;
        }

        if (storage.ss_family == AF_INET) {
            return get_sin()->sin_addr.s_addr == other.get_sin()->sin_addr.s_addr;
        }

        if (storage.ss_family == AF_INET6) {
            return std::memcmp(get_sin6()->sin6_addr.s6_addr, other.get_sin6()->sin6_addr.s6_addr, 16) == 0;
        }

        return false;
    }

    sockaddr_in* get_sin() { return reinterpret_cast<sockaddr_in*>(&storage); }
    const sockaddr_in* get_sin() const { return reinterpret_cast<const sockaddr_in*>(&storage); }
    sockaddr_in6* get_sin6() { return reinterpret_cast<sockaddr_in6*>(&storage); }
    const sockaddr_in6* get_sin6() const { return reinterpret_cast<const sockaddr_in6*>(&storage); }

    [[nodiscard]] uint16_t get_port() const noexcept {
        return (storage.ss_family == AF_INET) ? ntohs(get_sin()->sin_port) : ntohs(get_sin6()->sin6_port);
    }

private:
    sockaddr_in* get_sin_internal() { return reinterpret_cast<sockaddr_in*>(&storage); }
    sockaddr_in6* get_sin6_internal() { return reinterpret_cast<sockaddr_in6*>(&storage); }
};

namespace std {
    template<>
    struct hash<NetAddress> {
        size_t operator()(const NetAddress& addr) const noexcept {
            size_t h = 0;
            if (addr.storage.ss_family == AF_INET) {
                h = std::hash<uint32_t>{}(addr.get_sin()->sin_addr.s_addr);
            } else if (addr.storage.ss_family == AF_INET6) {
                uint64_t part;
                std::memcpy(&part, addr.get_sin6()->sin6_addr.s6_addr, 8);
                h = std::hash<uint64_t>{}(part);
            }
            return h ^ (std::hash<uint16_t>{}(addr.get_port()) << 1);
        }
    };
}