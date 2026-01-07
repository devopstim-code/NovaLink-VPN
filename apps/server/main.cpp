/*****************************************************************//**
* \file  main.cpp (Server)
* \brief  The NovaLink VPN server entry point.
* * Manages client sessions, stores the routing table (route_table)
* and coordinates the transfer of encrypted data between network participants.
* *\author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/

#include "core/network/EpollEngine.hpp"
#include "core/network/UdpSocket.hpp"
#include "core/tunnel/TunDevice.hpp"
#include "core/crypto/CryptoEngine.hpp"

#include <iostream>
#include <vector>
#include <csignal>
#include <atomic>
#include <memory>
#include <chrono>
#include <format>
#include <arpa/inet.h>
#include <cstring>
#include <unordered_map>
#include <utility>

#include "core/network/SslLayer.hpp"

namespace {
    const std::atomic<bool> global_running{true};
}

void signal_handler([[maybe_unused]] int sig) {
    const_cast<std::atomic<bool>&>(global_running).store(false);
}

enum class PacketType : uint8_t {
    Handshake = 0x01,
    Data      = 0x02
};

struct StringHash {
    using is_transparent = void;
    size_t operator()(std::string_view sv) const { return std::hash<std::string_view>{}(sv); }
};

struct ClientSession {
    std::unique_ptr<CryptoEngine> crypto;
    NetAddress address;
    uint32_t internal_ip;
    std::chrono::steady_clock::time_point last_seen;
};

using SessionMap = std::unordered_map<std::string, std::shared_ptr<ClientSession>, StringHash, std::equal_to<>>;
using RouteTable = std::unordered_map<uint32_t, std::shared_ptr<ClientSession>>;

struct HandshakeContext {
    std::span<const std::byte> data;
    const NetAddress& sender;
    const std::vector<std::byte>& srv_priv;
    const std::vector<std::byte>& srv_pub;
    UdpSocket& udp;
    SessionMap& sessions;
    RouteTable& route_table;
};

struct ServerContext {
    UdpSocket& udp;
    TunDevice& tun;
    SessionMap& sessions;
    RouteTable& route_table;
    const std::vector<std::byte>& srv_priv;
    const std::vector<std::byte>& srv_pub;
};

std::string address_to_key(const NetAddress& addr) {
    char ip_str[INET_ADDRSTRLEN];
    const auto* saddr = reinterpret_cast<const struct sockaddr_in*>(&addr.storage);
    inet_ntop(AF_INET, &(saddr->sin_addr), ip_str, INET_ADDRSTRLEN);
    return std::format("{}:{}", ip_str, ntohs(saddr->sin_port));
}

void handle_client_handshake(const HandshakeContext& ctx) {
    if (ctx.data.size() < 37) {
        std::cerr << "[Handshake] Packet too small from " << address_to_key(ctx.sender) << std::endl;
        return;
    }
    std::vector<std::byte> client_pub(32);
    std::memcpy(client_pub.data(), ctx.data.data() + 1, 32);
    uint32_t requested_ip;
    std::memcpy(&requested_ip, ctx.data.data() + 33, sizeof(requested_ip));

    try {
        auto shared = CryptoEngine::derive_shared_secret(ctx.srv_priv, client_pub);
        auto session = std::make_shared<ClientSession>();

        session->crypto = std::make_unique<CryptoEngine>(shared);
        session->address = ctx.sender;
        session->internal_ip = requested_ip;
        session->last_seen = std::chrono::steady_clock::now();

        const std::string key = address_to_key(ctx.sender);
        ctx.sessions[key] = session;
        ctx.route_table[requested_ip] = session;

        std::vector<std::byte> answer;
        answer.reserve(1 + ctx.srv_pub.size());
        answer.push_back(static_cast<std::byte>(PacketType::Handshake));
        answer.insert(answer.end(), ctx.srv_pub.begin(), ctx.srv_pub.end());

        auto ssl_masked_answer = SslLayer::wrap(answer, SslLayer::RECORD_HANDSHAKE);

        (void)ctx.udp.send(ssl_masked_answer, ctx.sender);

        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &requested_ip, ip_buf, INET_ADDRSTRLEN);
        std::cout << std::format("[Handshake] SUCCESS: {} registered as {}\n", key, ip_buf);

    } catch (const std::exception& e) {
        std::cerr << std::format("[Handshake] Error during derivation for {}: {}\n",
                                address_to_key(ctx.sender), e.what());
    }
}
void handle_network_traffic(ServerContext& s_ctx) {
    std::byte buf[4096];
    NetAddress sender;
    ssize_t len = s_ctx.udp.receive(buf, sender);
    if (len <= 0) return;
    auto raw_data = SslLayer::unwrap(std::span{buf, static_cast<size_t>(len)});
    if (raw_data.empty()) return;

    const auto p_type = static_cast<uint8_t>(raw_data[0]);

    if (p_type == std::to_underlying(PacketType::Handshake)) {
        handle_client_handshake({raw_data, sender, s_ctx.srv_priv, s_ctx.srv_pub, s_ctx.udp, s_ctx.sessions, s_ctx.route_table});
    }
    else if (p_type == std::to_underlying(PacketType::Data)) {
        if (auto it = s_ctx.sessions.find(address_to_key(sender)); it != s_ctx.sessions.end()) {
            auto decrypted = it->second->crypto->decrypt(raw_data.subspan(1));
            s_ctx.tun.write_packet(decrypted);
            it->second->last_seen = std::chrono::steady_clock::now();
        }
    }
}


void handle_tunnel_traffic(ServerContext& s_ctx) {
    s_ctx.tun.read_all_packets([&s_ctx](std::span<const std::byte> packet) {
        if (packet.size() < 20) return;

        uint32_t dest_ip;
        std::memcpy(&dest_ip, packet.data() + 16, sizeof(dest_ip));

        if (auto it = s_ctx.route_table.find(dest_ip); it != s_ctx.route_table.end()) {
            auto encrypted = it->second->crypto->encrypt(packet);

            std::vector<std::byte> final_pkt;
            final_pkt.reserve(encrypted.size() + 1);
            final_pkt.push_back(static_cast<std::byte>(PacketType::Data));
            final_pkt.insert(final_pkt.end(), encrypted.begin(), encrypted.end());
            auto ssl_pkt = SslLayer::wrap(final_pkt, SslLayer::RECORD_APPLICATION_DATA);
            (void)s_ctx.udp.send(ssl_pkt, it->second->address);
        }
    });
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << std::format("Usage: {} <listen_port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    SessionMap sessions;
    RouteTable route_table;

    try {
        const auto listen_port = static_cast<uint16_t>(std::stoi(argv[1]));
        auto tun = std::make_unique<TunDevice>("nova_srv");
        auto udp = std::make_unique<UdpSocket>(AF_INET);
        udp->bind(listen_port);

        std::vector<std::byte> srv_priv, srv_pub;
        CryptoEngine::generate_ecdh_keys(srv_priv, srv_pub);

        tun->up("10.8.0.1", "255.255.255.0");

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};
        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        ServerContext s_ctx{*udp, *tun, sessions, route_table, srv_priv, srv_pub};
        std::cout << std::format("[NovaLink Server] Started on port {}\n", listen_port);

        std::vector<epoll_event> event_buffer(16);

        while (global_running.load()) {
            int nfds = engine.wait(event_buffer, 100);
            for (int n = 0; n < nfds; ++n) {
                const auto* event_ctx = static_cast<const EventContext*>(event_buffer[n].data.ptr);
                if (event_ctx->fd == udp->get_fd()) {
                    handle_network_traffic(s_ctx);
                } else if (event_ctx->fd == tun->get_fd()) {
                    handle_tunnel_traffic(s_ctx);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << std::format("[Critical] {}\n", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}