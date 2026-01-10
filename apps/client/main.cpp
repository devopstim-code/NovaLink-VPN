/*****************************************************************//**
* \file  main.cpp (Client)
* \brief  NovaLink VPN client entry point.
* * Establishes a connection to the server, performs the handshake
* and creates a local tunnel for secure network access.
* * \author Devopstim
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
#include <vector>
#include <csignal>
#include <atomic>
#include <memory>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <openssl/crypto.h>

using namespace NovaProtocol;

namespace {
    std::atomic<bool> global_running{true};
}

void handle_signal(int) { global_running.store(false); }

struct ClientContext {
    UdpSocket& udp;
    TunDevice& tun;
    const NetAddress& server_addr;
    std::unique_ptr<CryptoEngine> crypto;
    bool handshaked = false;

    std::vector<std::byte> my_priv, my_pub;
    std::vector<std::byte> kyber_priv, kyber_pub;
};
bool is_server(const NetAddress& sender, const NetAddress& server) {
    return (sender.get_port() == server.get_port()) && sender.is_same_ip(server);
}

void send_handshake(ClientContext& ctx, uint32_t v_ip) {
    static thread_local std::byte handshake_buf[Sizes::MTU];
    std::memset(handshake_buf, 0, Sizes::MTU);

    size_t ptr = 5;
    handshake_buf[ptr++] = static_cast<std::byte>(PacketType::Handshake);

    uint16_t c_len = static_cast<uint16_t>(ctx.my_pub.size());
    set_u16(handshake_buf + ptr, c_len);
    ptr += 2;
    std::memcpy(handshake_buf + ptr, ctx.my_pub.data(), c_len);
    ptr += c_len;

    uint16_t q_len = static_cast<uint16_t>(ctx.kyber_pub.size());
    set_u16(handshake_buf + ptr, q_len);
    ptr += 2;
    std::memcpy(handshake_buf + ptr, ctx.kyber_pub.data(), q_len);
    ptr += q_len;

    std::memcpy(handshake_buf + ptr, &v_ip, 4);
    ptr += 4;

    auto final_span = SslLayer::wrap_inplace({handshake_buf, Sizes::MTU}, ptr - 5, SslLayer::RECORD_HANDSHAKE);
    ctx.udp.send(final_span, ctx.server_addr);
    std::cout << "[UDP] Handshake sent to server..." << std::endl;
}

void handle_udp_event(ClientContext& ctx) {
    static thread_local std::byte net_buf[Sizes::MTU];
    NetAddress sender;

    ssize_t received = ctx.udp.receive(net_buf, sender);
    if (received <= 5) return;
    std::cout << "[UDP] Received " << received << " bytes from " << sender.to_string() << std::endl;

    if (!is_server(sender, ctx.server_addr)) {
        std::cout << "[DEBUG] Filter failed: Sender " << sender.to_string()
                  << " != Expected " << ctx.server_addr.to_string() << std::endl;
        return;
    }

    auto payload = SslLayer::unwrap_inplace({net_buf, static_cast<size_t>(received)});
    if (payload.empty()) {
        std::cout << "[DEBUG] SSL Unwrap failed!" << std::endl;
        return;
    }
    const auto p_type = static_cast<PacketType>(payload[0]);

    if (p_type == PacketType::Handshake && !ctx.handshaked) {
        try {
            size_t offset = 1;
            uint16_t s_c_len = get_u16(payload.data() + offset);
            offset += 2;
            std::vector<std::byte> srv_pub(payload.data() + offset, payload.data() + offset + s_c_len);
            offset += s_c_len;

            uint16_t s_q_len = get_u16(payload.data() + offset);
            offset += 2;

            std::vector<std::byte> hybrid_secret;
            auto ecdh_ss = CryptoEngine::derive_shared_secret(ctx.my_priv, srv_pub);
            hybrid_secret.insert(hybrid_secret.end(), ecdh_ss.begin(), ecdh_ss.end());

            if (s_q_len > 0) {
                std::span<const std::byte> ct{payload.data() + offset, s_q_len};
                auto pq_ss = CryptoEngine::kyber_decapsulate(ct, ctx.kyber_priv);
                hybrid_secret.insert(hybrid_secret.end(), pq_ss.begin(), pq_ss.end());
            }

            ctx.crypto = std::make_unique<CryptoEngine>(hybrid_secret);
            ctx.handshaked = true;

            OPENSSL_cleanse(ctx.my_priv.data(), ctx.my_priv.size());
            OPENSSL_cleanse(ctx.kyber_priv.data(), ctx.kyber_priv.size());

            std::cout << "[NovaLink] SUCCESS! Quantum-Safe Tunnel established." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[Handshake Error] " << e.what() << std::endl;
        }
    }
    else if (p_type == PacketType::Data && ctx.handshaked) {
        size_t out_len = 0;
        if (ctx.crypto->decrypt_inplace(payload, 1, payload.size() - 1, out_len)) {
            ctx.tun.write_packet({payload.data() + 1 + CryptoEngine::IV_SIZE, out_len});
        }
    }
}

void handle_tun_event(ClientContext& ctx) {
    static thread_local std::byte tun_buf[Sizes::MTU];
    constexpr size_t header_room = 5 + 1 + CryptoEngine::IV_SIZE;

    ctx.tun.read_all_packets([&](std::span<const std::byte> packet) {
        if (!ctx.handshaked || packet.size() > (Sizes::MTU - header_room - 16)) return;

        std::memcpy(tun_buf + header_room, packet.data(), packet.size());
        size_t enc_len = 0;
        ctx.crypto->encrypt_inplace({tun_buf, Sizes::MTU}, header_room, packet.size(), enc_len);

        tun_buf[5] = static_cast<std::byte>(PacketType::Data);
        auto final_span = SslLayer::wrap_inplace({tun_buf, Sizes::MTU},
                                                enc_len + 1 + CryptoEngine::IV_SIZE,
                                                SslLayer::RECORD_APPLICATION_DATA);
        ctx.udp.send(final_span, ctx.server_addr);
    });
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <srv_ip> <port> <my_tun_ip>\n";
        return 1;
    }
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        NetAddress server_addr(argv[1], static_cast<uint16_t>(std::stoi(argv[2])));
        uint32_t my_v_ip = inet_addr(argv[3]);

        auto tun = std::make_unique<TunDevice>("nova_cl");
        auto udp = std::make_unique<UdpSocket>(AF_INET);
        tun->up(argv[3], "255.255.255.0");

        ClientContext c_ctx{*udp, *tun, server_addr};
        CryptoEngine::generate_ecdh_keys(c_ctx.my_priv, c_ctx.my_pub);
        CryptoEngine::generate_kyber_keys(c_ctx.kyber_priv, c_ctx.kyber_pub);

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};
        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        std::vector<epoll_event> events(64);
        auto last_handshake = std::chrono::steady_clock::now();

        std::cout << "[NovaLink] Connecting to quantum-safe server " << argv[1] << "...\n";

        while (global_running.load(std::memory_order_relaxed)) {
            auto now = std::chrono::steady_clock::now();
            if (!c_ctx.handshaked) {
                if (now - last_handshake > std::chrono::seconds(2)) {
                    send_handshake(c_ctx, my_v_ip);
                    last_handshake = now;
                }
            }

            int nfds = engine.wait(events, 100);

            for (int i = 0; i < nfds; ++i) {
                auto* ctx = static_cast<EventContext*>(events[i].data.ptr);
                if (ctx->fd == udp->get_fd()) handle_udp_event(c_ctx);
                else if (ctx->fd == tun->get_fd()) handle_tun_event(c_ctx);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[Critical Client Error] " << e.what() << "\n";
        return 1;
    }

    std::cout << "[NovaLink] Client shutdown complete.\n";
    return 0;
}