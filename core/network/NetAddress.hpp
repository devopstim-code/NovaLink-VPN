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
#include <array>

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

    [[nodiscard]] const sockaddr_in& as_v4() const noexcept {
        return *static_cast<const sockaddr_in*>(static_cast<const void*>(&storage));
    }

    [[nodiscard]] const sockaddr_in6& as_v6() const noexcept {
        return *static_cast<const sockaddr_in6*>(static_cast<const void*>(&storage));
    }

    [[nodiscard]] sockaddr_in& as_v4_internal() noexcept {
        return *static_cast<sockaddr_in*>(static_cast<void*>(&storage));
    }

    [[nodiscard]] sockaddr_in6& as_v6_internal() noexcept {
        return *static_cast<sockaddr_in6*>(static_cast<void*>(&storage));
    }

    explicit NetAddress(const std::string& ip, uint16_t port) {
        std::memset(&storage, 0, sizeof(storage));

        if (inet_pton(AF_INET, ip.c_str(), &as_v4_internal().sin_addr) > 0) {
            as_v4_internal().sin_family = AF_INET;
            as_v4_internal().sin_port = htons(port);
            len = sizeof(sockaddr_in);
        } else if (inet_pton(AF_INET6, ip.c_str(), &as_v6_internal().sin6_addr) > 0) {
            as_v6_internal().sin6_family = AF_INET6;
            as_v6_internal().sin6_port = htons(port);
            len = sizeof(sockaddr_in6);
        } else {
            throw NetworkException(std::format("Invalid IP format: {}", ip));
        }
    }

    [[nodiscard]] std::string to_string() const {
        std::string ip_str(INET6_ADDRSTRLEN, '\0');

        if (storage.ss_family == AF_INET) {
            inet_ntop(AF_INET, &as_v4().sin_addr, ip_str.data(), INET_ADDRSTRLEN);
        } else if (storage.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &as_v6().sin6_addr, ip_str.data(), INET6_ADDRSTRLEN);
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
            auto check_mapped = [](const sockaddr_in6& a6, const sockaddr_in& a4) {
                static constexpr std::array<uint8_t, 12> ipv4_prefix = {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
                };
                return std::memcmp(a6.sin6_addr.s6_addr, ipv4_prefix.data(), 12) == 0 &&
                       std::memcmp(a6.sin6_addr.s6_addr + 12, &a4.sin_addr.s_addr, 4) == 0;
            };

            if (storage.ss_family == AF_INET6 && other.storage.ss_family == AF_INET)
                return check_mapped(as_v6(), other.as_v4());
            if (storage.ss_family == AF_INET && other.storage.ss_family == AF_INET6)
                return check_mapped(other.as_v6(), as_v4());

            return false;
        }

        if (storage.ss_family == AF_INET) {
            return as_v4().sin_addr.s_addr == other.as_v4().sin_addr.s_addr;
        }
        if (storage.ss_family == AF_INET6) {
            return std::memcmp(as_v6().sin6_addr.s6_addr, other.as_v6().sin6_addr.s6_addr, 16) == 0;
        }
        return false;
    }

    [[nodiscard]] const sockaddr* get_sockaddr() const noexcept {
        return reinterpret_cast<const sockaddr*>(&storage);
    }

    [[nodiscard]] uint16_t get_port() const noexcept {
        return (storage.ss_family == AF_INET) ? ntohs(as_v4().sin_port) : ntohs(as_v6().sin6_port);
    }
};

namespace std {
    template<>
    struct hash<NetAddress> {
        size_t operator()(const NetAddress& addr) const noexcept {
            size_t h = 0;
            if (addr.storage.ss_family == AF_INET) {
                h = std::hash<uint32_t>{}(addr.as_v4().sin_addr.s_addr);
            } else if (addr.storage.ss_family == AF_INET6) {
                uint64_t part;
                std::memcpy(&part, addr.as_v6().sin6_addr.s6_addr, 8);
                h = std::hash<uint64_t>{}(part);
            }
            return h ^ (std::hash<uint16_t>{}(addr.get_port()) << 1);
        }
    };
}