#include "SslLayer.hpp"
#include <cstring>
#include <netinet/in.h>

std::vector<std::byte> SslLayer::wrap(std::span<const std::byte> data, uint8_t type) {
    std::vector<std::byte> tls_pkt;
    tls_pkt.reserve(5 + data.size());
    tls_pkt.push_back(static_cast<std::byte>(type));
    tls_pkt.push_back(static_cast<std::byte>(TLS_VERSION_MAJOR));
    tls_pkt.push_back(static_cast<std::byte>(TLS_VERSION_MINOR));

    uint16_t len = htons(static_cast<uint16_t>(data.size()));
    const auto* len_ptr = reinterpret_cast<const std::byte*>(&len);
    tls_pkt.push_back(len_ptr[0]);
    tls_pkt.push_back(len_ptr[1]);
    tls_pkt.insert(tls_pkt.end(), data.begin(), data.end());

    return tls_pkt;
}

std::span<const std::byte> SslLayer::unwrap(std::span<const std::byte> tls_packet) {
    if (tls_packet.size() < 5) return {};
    uint8_t type = static_cast<uint8_t>(tls_packet[0]);
    if (type != RECORD_HANDSHAKE && type != RECORD_APPLICATION_DATA) return {};
    if (tls_packet[1] != static_cast<std::byte>(TLS_VERSION_MAJOR)) return {};

    uint16_t net_len;
    std::memcpy(&net_len, tls_packet.data() + 3, 2);
    uint16_t host_len = ntohs(net_len);

    if (static_cast<size_t>(host_len) + 5 > tls_packet.size()) return {};
    return tls_packet.subspan(5, host_len);
}