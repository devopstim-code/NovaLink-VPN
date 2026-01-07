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

#include <iostream>
#include <vector>
#include <csignal>
#include <atomic>
#include <memory>
#include <chrono>
#include <format>
#include <arpa/inet.h>
#include <cstring>
#include <utility>

#include "core/network/SslLayer.hpp"

namespace {
    const std::atomic<bool> global_running{true};
}

void handle_signal([[maybe_unused]] int sig) {
    const_cast<std::atomic<bool>&>(global_running).store(false);
}

enum class PacketType : uint8_t {
    Handshake = 0x01,
    Data      = 0x02
};

struct ClientContext {
    UdpSocket& udp;
    TunDevice& tun;
    const NetAddress& server_addr;
    std::unique_ptr<CryptoEngine>& crypto;
    bool& handshaked;
    const std::vector<std::byte>& my_priv;
    const std::vector<std::byte>& my_pub;
};
void send_handshake(const ClientContext& ctx, const std::string& v_ip_str) {
    std::vector<std::byte> hello;
    hello.push_back(static_cast<std::byte>(PacketType::Handshake));
    hello.insert(hello.end(), ctx.my_pub.begin(), ctx.my_pub.end());

    uint32_t my_v_ip;
    if (inet_pton(AF_INET, v_ip_str.c_str(), &my_v_ip) <= 0) return;
    const auto* ip_bytes = reinterpret_cast<const std::byte*>(&my_v_ip);
    hello.insert(hello.end(), ip_bytes, ip_bytes + sizeof(my_v_ip));

    // МАСКИРОВКА: Оборачиваем пакет в TLS заголовок
    auto ssl_pkt = SslLayer::wrap(hello, SslLayer::RECORD_HANDSHAKE);

    if (ctx.udp.send(ssl_pkt, ctx.server_addr) < 0) {
        std::cerr << "[Handshake] Failed to send packet" << std::endl;
    } else {
        std::cout << "[Handshake] Sending public key + IP (SSL masked)..." << std::endl;
    }
}

void handle_udp_event(ClientContext& ctx) {
    std::byte buf[4096];
    NetAddress sender;
    ssize_t len = ctx.udp.receive(buf, sender);
    if (len <= 0) return;

    // ДЕМАСКИРОВКА: Проверяем TLS заголовок и достаем полезную нагрузку
    auto raw_data = SslLayer::unwrap(std::span{buf, static_cast<size_t>(len)});
    if (raw_data.empty()) return; // Пакет не прошел проверку TLS-маскировки

    const auto p_type = static_cast<uint8_t>(raw_data[0]);

    if (p_type == std::to_underlying(PacketType::Handshake) && !ctx.handshaked) {
        if (raw_data.size() < 33) return;

        std::vector<std::byte> srv_pub(32);
        std::memcpy(srv_pub.data(), raw_data.data() + 1, 32);

        auto shared = CryptoEngine::derive_shared_secret(ctx.my_priv, srv_pub);
        ctx.crypto = std::make_unique<CryptoEngine>(shared);
        ctx.handshaked = true;
        std::cout << "[Handshake] SUCCESS! Encryption established." << std::endl;
    }
    else if (p_type == std::to_underlying(PacketType::Data) && ctx.handshaked) {
        // Убираем 1 байт PacketType::Data и расшифровываем
        auto decrypted = ctx.crypto->decrypt(raw_data.subspan(1));
        ctx.tun.write_packet(decrypted);
    }
}

void handle_tun_event(ClientContext& ctx) {
    ctx.tun.read_all_packets([&ctx](std::span<const std::byte> packet) {
        if (!ctx.crypto) return;

        auto encrypted = ctx.crypto->encrypt(packet);

        std::vector<std::byte> final_pkt;
        final_pkt.reserve(encrypted.size() + 1);
        final_pkt.push_back(static_cast<std::byte>(PacketType::Data));
        final_pkt.insert(final_pkt.end(), encrypted.begin(), encrypted.end());

        // МАСКИРОВКА: Весь зашифрованный пакет теперь выглядит как TLS Application Data
        auto ssl_pkt = SslLayer::wrap(final_pkt, SslLayer::RECORD_APPLICATION_DATA);
        (void)ctx.udp.send(ssl_pkt, ctx.server_addr);
    });
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << std::format("Usage: {} <server_ip> <port> <virtual_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        const std::string v_ip_str = argv[3];
        const std::string if_name = "nova1";

        auto tun = std::make_unique<TunDevice>(if_name);
        auto udp = std::make_unique<UdpSocket>(AF_INET);
        NetAddress server_addr(argv[1], static_cast<uint16_t>(std::stoi(argv[2])));

        std::vector<std::byte> my_priv, my_pub;
        CryptoEngine::generate_ecdh_keys(my_priv, my_pub);

        std::unique_ptr<CryptoEngine> crypto;
        bool handshaked = false;

        tun->up(v_ip_str, "255.255.255.0");

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};
        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        ClientContext c_ctx{*udp, *tun, server_addr, crypto, handshaked, my_priv, my_pub};
        std::cout << std::format("[NovaLink] Client {} started.\n", v_ip_str);

        std::vector<epoll_event> event_buffer(16);
        auto last_hello = std::chrono::steady_clock::now();

        while (global_running.load()) {
            auto now = std::chrono::steady_clock::now();
            if (!handshaked && std::chrono::duration_cast<std::chrono::seconds>(now - last_hello).count() >= 2) {
                send_handshake(c_ctx, v_ip_str);
                last_hello = now;
            }

            int nfds = engine.wait(event_buffer, 100);
            for (int n = 0; n < nfds; ++n) {
                const auto* event_ctx = static_cast<const EventContext*>(event_buffer[n].data.ptr);
                if (event_ctx->fd == udp->get_fd()) {
                    handle_udp_event(c_ctx);
                }
                else if (event_ctx->fd == tun->get_fd() && handshaked) {
                    handle_tun_event(c_ctx);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << std::format("[Critical] {}\n", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}