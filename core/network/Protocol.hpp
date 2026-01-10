/*****************************************************************//**
* \file  Protocol.hpp
* \brief NovaLink Binary Wire Protocol Specification.
 * * Defines the binary layout for encrypted packets, handshake structures,
 * and protocol constants. This header ensures consistent memory mapping
 * between the server and client components.
**\author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/


#pragma once
#include <vector>
#include <cstddef>
#include <cstring>
#include <functional>

namespace NovaProtocol {

    enum class PacketType : uint8_t {
        Handshake = 0x01,
        Data      = 0x02,
        Ping      = 0x03
    };

    struct Sizes {
        static constexpr size_t TYPE_SIZE    = 1;   // PacketType
        static constexpr size_t SSL_HEADER   = 5;   // TLS Header Simulation
        static constexpr size_t IV_SIZE      = 12;  // ChaCha20 IV
        static constexpr size_t TAG_SIZE     = 16;  // Poly1305 Tag
        static constexpr size_t MTU          = 1500;
        static constexpr size_t LEN_FIELD    = 2;   // Size of the key length field (uint16_t)

        // Quantum dimensions
        static constexpr size_t X25519_PUB   = 32;
        static constexpr size_t KYBER768_PUB = 1184;

        // Type(1) + CLen(2) + X25519(32) + QLen(2) + IP(4) = 41 byte
        static constexpr size_t MIN_HANDSHAKE_SIZE = TYPE_SIZE + LEN_FIELD + X25519_PUB + LEN_FIELD + 4;
    };

    struct DataOffset {
        static constexpr size_t SSL_HEADER_START = 0;
        static constexpr size_t IV_START         = 5;
        static constexpr size_t PAYLOAD_START    = 17; // 5 (SSL) + 12 (IV)
    };

    struct SessionKey {
        uint32_t ip;
        uint16_t port;

        bool operator==(const SessionKey& other) const {
            return ip == other.ip && port == other.port;
        }
    };

    struct SessionKeyHash {
        std::size_t operator()(const SessionKey& k) const {
            return (static_cast<size_t>(k.ip) << 16) | k.port;
        }
    };
    inline std::ostream& operator<<(std::ostream& os, const SessionKey& key) {
        os << key.ip << ":" << key.port;
        return os;
    }
    inline uint16_t get_u16(const std::byte* ptr) {
        if (!ptr) return 0;
        uint16_t val;
        std::memcpy(&val, ptr, 2);
        return val;
    }
    inline void set_u16(std::byte* ptr, uint16_t val) {
        std::memcpy(ptr, &val, 2);
    }
    inline void set_u16_to_vec(std::vector<std::byte>& vec, uint16_t val) {
        vec.push_back(static_cast<std::byte>(val & 0xFF));
        vec.push_back(static_cast<std::byte>((val >> 8) & 0xFF));
    }
}