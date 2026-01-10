/*****************************************************************//**
* @file SslLayer.hpp
 * @brief Obfuscation layer using TLS 1.2 Record Layer framing.
 * * Provides encapsulation of raw UDP payloads into dummy TLS records to
 * bypass Deep Packet Inspection (DPI). This layer does not implement
 * full TLS handshake but mimics its wire format for stealth.
**\author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/

#pragma once
#include <vector>
#include <cstddef>
#include <span>
#include <cstdint>

class SslLayer {
public:
    static constexpr uint8_t RECORD_HANDSHAKE = 0x16;
    static constexpr uint8_t RECORD_APPLICATION_DATA = 0x17;
    static std::span<std::byte> wrap_inplace(std::span<std::byte> buffer, size_t payload_len, uint8_t type);
    static std::span<std::byte> unwrap_inplace(std::span<std::byte> tls_packet);
    static std::vector<std::byte> wrap(std::span<const std::byte> data, uint8_t type = RECORD_APPLICATION_DATA);

private:
    static constexpr uint8_t TLS_VERSION_MAJOR = 0x03;
    static constexpr uint8_t TLS_VERSION_MINOR = 0x03;
};