#pragma once
#include <vector>
#include <cstddef>
#include <span>
#include <cstdint>

class SslLayer {
public:
    // TLS Record Types
    static constexpr uint8_t RECORD_HANDSHAKE = 0x16;
    static constexpr uint8_t RECORD_APPLICATION_DATA = 0x17;
    static std::vector<std::byte> wrap(std::span<const std::byte> data, uint8_t type = RECORD_APPLICATION_DATA);
    static std::span<const std::byte> unwrap(std::span<const std::byte> tls_packet);

private:
    static constexpr uint8_t TLS_VERSION_MAJOR = 0x03;
    static constexpr uint8_t TLS_VERSION_MINOR = 0x03;
};