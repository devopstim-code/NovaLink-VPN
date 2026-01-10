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
#include "core/network/Protocol.hpp"
#include "core/network/SslLayer.hpp"

#include <iostream>
#include <csignal>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <cstring>
#include <arpa/inet.h>

using namespace NovaProtocol;

namespace {
    std::atomic<bool> global_running{true};
}
void signal_handler(int) { global_running.store(false); }

struct ClientSession {
    std::unique_ptr<CryptoEngine> crypto;
    NetAddress address;
    uint32_t internal_ip = 0;
    std::chrono::steady_clock::time_point last_seen;
};

using SessionMap = std::unordered_map<SessionKey, std::shared_ptr<ClientSession>, SessionKeyHash>;
using RouteTable = std::unordered_map<uint32_t, std::shared_ptr<ClientSession>>;

struct ServerContext {
    UdpSocket& udp;
    TunDevice& tun;
    SessionMap& sessions;
    RouteTable& route_table;
    const std::vector<std::byte>& srv_priv;
    const std::vector<std::byte>& srv_pub;
    const size_t MAX_SESSIONS = 1000;
};

SessionKey get_key_from_addr(const NetAddress& addr) {
    if (addr.storage.ss_family == AF_INET) {
        auto* s = reinterpret_cast<const sockaddr_in*>(&addr.storage);
        return { s->sin_addr.s_addr, s->sin_port };
    } else {
        auto* s = reinterpret_cast<const sockaddr_in6*>(&addr.storage);
        uint32_t hash_ip = 0;
        std::memcpy(&hash_ip, &s->sin6_addr, 4);
        return { hash_ip, s->sin6_port };
    }
}

void handle_client_handshake(const NetAddress& sender, std::span<const std::byte> raw_data, ServerContext& ctx) {
    if (ctx.sessions.size() >= 1000) {
        std::cerr << "[Security] Too many sessions. Drop handshake from " << sender.to_string() << "\n";
        return;
    }

    try {
        if (raw_data.size() < Sizes::MIN_HANDSHAKE_SIZE) return;
        size_t offset = 1;
        uint16_t c_len = get_u16(raw_data.data() + offset);
        offset += 2;
        if (offset + c_len > raw_data.size() || c_len != 32) return;
        std::vector<std::byte> client_classic_pub(raw_data.data() + offset, raw_data.data() + offset + c_len);
        offset += c_len;

        if (offset + 2 > raw_data.size()) return;
        uint16_t q_len = get_u16(raw_data.data() + offset);
        offset += 2;
        if (q_len != CryptoEngine::KYBER768_PUB || offset + q_len > raw_data.size()) {
            std::cerr << "[Security] Missing or invalid Kyber key from " << sender.to_string() << "\n";
            return;
        }

        std::vector<std::byte> client_kyber_pub(raw_data.data() + offset, raw_data.data() + offset + q_len);
        offset += q_len;

        auto ecdh_secret = CryptoEngine::derive_shared_secret(ctx.srv_priv, client_classic_pub);
        auto [kyber_ct, kyber_ss] = CryptoEngine::kyber_encapsulate(client_kyber_pub);

        std::vector<std::byte> hybrid_secret;
        hybrid_secret.reserve(ecdh_secret.size() + kyber_ss.size());
        hybrid_secret.insert(hybrid_secret.end(), ecdh_secret.begin(), ecdh_secret.end());
        hybrid_secret.insert(hybrid_secret.end(), kyber_ss.begin(), kyber_ss.end());

        if (offset + 4 > raw_data.size()) return;
        uint32_t req_ip;
        std::memcpy(&req_ip, raw_data.data() + offset, 4);

        auto session = std::make_shared<ClientSession>();
        session->crypto = std::make_unique<CryptoEngine>(hybrid_secret);
        session->address = sender;
        session->internal_ip = req_ip;
        session->last_seen = std::chrono::steady_clock::now();

        ctx.sessions[get_key_from_addr(sender)] = session;
        ctx.route_table[req_ip] = session;
        std::vector<std::byte> ans;
        ans.push_back(static_cast<std::byte>(PacketType::Handshake));
        set_u16_to_vec(ans, static_cast<uint16_t>(ctx.srv_pub.size()));
        ans.insert(ans.end(), ctx.srv_pub.begin(), ctx.srv_pub.end());
        set_u16_to_vec(ans, static_cast<uint16_t>(kyber_ct.size()));
        ans.insert(ans.end(), kyber_ct.begin(), kyber_ct.end());

        auto ssl_ans = SslLayer::wrap(ans, SslLayer::RECORD_HANDSHAKE);
        (void)ctx.udp.send(ssl_ans, sender);

    } catch (const std::exception& e) {
        std::cerr << "[Crypto Error] Handshake failed: " << e.what() << "\n";
    }
}
void handle_network_traffic(ServerContext& s_ctx) {
    static thread_local std::byte net_buf[Sizes::MTU];
    NetAddress sender;

    ssize_t received = s_ctx.udp.receive(net_buf, sender);
    if (received <= 5) return;

    auto payload = SslLayer::unwrap_inplace({net_buf, static_cast<size_t>(received)});
    if (payload.empty()) return;

    const auto p_type = static_cast<PacketType>(payload[0]);

    if (p_type == PacketType::Handshake) {
        handle_client_handshake(sender, payload, s_ctx);
    }
    else if (p_type == PacketType::Data) {
        auto it = s_ctx.sessions.find(get_key_from_addr(sender));
        if (it != s_ctx.sessions.end()) {
            size_t out_len = 0;
            if (it->second->crypto->decrypt_inplace(payload, 1, payload.size() - 1, out_len)) {
                s_ctx.tun.write_packet({payload.data() + 1 + CryptoEngine::IV_SIZE, out_len});
                it->second->last_seen = std::chrono::steady_clock::now();
            }
        }
    }
}

void handle_tunnel_traffic(ServerContext& s_ctx) {
    static thread_local std::byte tun_work_buf[Sizes::MTU];
    constexpr size_t crypto_header = 1 + CryptoEngine::IV_SIZE;
    constexpr size_t total_header = 5 + crypto_header;

    s_ctx.tun.read_all_packets([&](std::span<const std::byte> packet) {
        if (packet.size() < 20 || packet.size() > (Sizes::MTU - total_header - 16)) return;

        uint32_t dest_ip;
        std::memcpy(&dest_ip, packet.data() + 16, 4);

        auto it = s_ctx.route_table.find(dest_ip);
        if (it != s_ctx.route_table.end()) {
            std::memcpy(tun_work_buf + total_header, packet.data(), packet.size());

            size_t encrypted_len = 0;
            it->second->crypto->encrypt_inplace({tun_work_buf, Sizes::MTU}, total_header, packet.size(), encrypted_len);

            tun_work_buf[5] = static_cast<std::byte>(PacketType::Data);

            auto final_span = SslLayer::wrap_inplace({tun_work_buf, Sizes::MTU}, encrypted_len + crypto_header, SslLayer::RECORD_APPLICATION_DATA);
            (void)s_ctx.udp.send(final_span, it->second->address);
        }
    });
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <listen_ip> <port> <tun_ip>\n";
        return 1;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    SessionMap sessions;
    RouteTable route_table;
    auto janitor_it = sessions.end();
    auto last_cleanup = std::chrono::steady_clock::now();
    try {
        uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
        auto tun = std::make_unique<TunDevice>("nova_srv");
        auto udp = std::make_unique<UdpSocket>(AF_INET);

        udp->bind(port);
        tun->up(argv[3], "255.255.255.0");
        std::vector<std::byte> srv_priv, srv_pub;
        CryptoEngine::generate_ecdh_keys(srv_priv, srv_pub);

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};

        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        ServerContext s_ctx{*udp, *tun, sessions, route_table, srv_priv, srv_pub};
        std::vector<epoll_event> events(64);

        std::cout << "[NovaLink] PQC Server started on port " << port << "...\n";

        while (global_running.load(std::memory_order_relaxed)) {
            int nfds = engine.wait(events, 50);

            for (int i = 0; i < nfds; ++i) {
                auto* ctx = static_cast<EventContext*>(events[i].data.ptr);
                if (ctx->fd == udp->get_fd()) handle_network_traffic(s_ctx);
                else if (ctx->fd == tun->get_fd()) handle_tunnel_traffic(s_ctx);
            }

            auto now = std::chrono::steady_clock::now();
            if (now - last_cleanup > std::chrono::milliseconds(500)) {
                if (sessions.empty()) {
                    janitor_it = sessions.end();
                } else {
                    if (janitor_it == sessions.end()) {
                        janitor_it = sessions.begin();
                    }
                    if (now - janitor_it->second->last_seen > std::chrono::minutes(10)) {
                        std::cout << "[Janitor] Closing inactive session: " << janitor_it->first << "\n";
                        route_table.erase(janitor_it->second->internal_ip);
                        janitor_it = sessions.erase(janitor_it);
                    } else {
                        ++janitor_it;
                    }
                }
                last_cleanup = now;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[Critical Server Error] " << e.what() << "\n";
        return 1;
    }

    std::cout << "[NovaLink] Server stopped gracefully.\n";
    return 0;
}