#include "SslLayer.hpp"
#include <cstring>
#include <netinet/in.h>

std::vector<std::byte> SslLayer::wrap(std::span<const std::byte> data, uint8_t type) {
    std::vector<std::byte> packet(5 + data.size());
    packet[0] = static_cast<std::byte>(type);
    packet[1] = static_cast<std::byte>(TLS_VERSION_MAJOR);
    packet[2] = static_cast<std::byte>(TLS_VERSION_MINOR);

    uint16_t net_len = htons(static_cast<uint16_t>(data.size()));
    std::memcpy(&packet[3], &net_len, 2);
    std::memcpy(packet.data() + 5, data.data(), data.size());
    return packet;
}

std::span<std::byte> SslLayer::wrap_inplace(std::span<std::byte> buffer, size_t payload_len, uint8_t type) {
    if (buffer.size() < payload_len + 5) {
        return {};
    }

    buffer[0] = static_cast<std::byte>(type);
    buffer[1] = static_cast<std::byte>(TLS_VERSION_MAJOR);
    buffer[2] = static_cast<std::byte>(TLS_VERSION_MINOR);

    uint16_t net_len = htons(static_cast<uint16_t>(payload_len));
    std::memcpy(buffer.data() + 3, &net_len, 2);

    return buffer.subspan(0, 5 + payload_len);
}

std::span<std::byte> SslLayer::unwrap_inplace(std::span<std::byte> tls_packet) {
    if (tls_packet.size() < 5) return {};

    uint8_t type = static_cast<uint8_t>(tls_packet[0]);
    if (type != RECORD_HANDSHAKE && type != RECORD_APPLICATION_DATA) return {};

    uint16_t net_len;
    std::memcpy(&net_len, tls_packet.data() + 3, 2);
    uint16_t host_len = ntohs(net_len);

    if (static_cast<size_t>(5) + host_len > tls_packet.size()) return {};

    return tls_packet.subspan(5, host_len);
}