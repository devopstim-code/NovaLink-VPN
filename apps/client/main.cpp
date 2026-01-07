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
#include <utility>
#include <format>
#include <arpa/inet.h>

namespace {
    std::atomic<bool> global_running{true};
}

void handle_signal([[maybe_unused]] int sig) {
    global_running.store(false);
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
    const std::vector<uint8_t>& my_priv;
    const std::vector<uint8_t>& my_pub;
};

void send_handshake(const ClientContext& ctx, const std::string& v_ip_str) {
    std::vector hello = { std::to_underlying(PacketType::Handshake) };
    hello.insert(hello.end(), ctx.my_pub.begin(), ctx.my_pub.end());

    uint32_t my_v_ip;
    if (inet_pton(AF_INET, v_ip_str.c_str(), &my_v_ip) <= 0) return;
    const auto* ip_bytes = static_cast<const uint8_t*>(static_cast<const void*>(&my_v_ip));
    hello.insert(hello.end(), ip_bytes, ip_bytes + 4);

    ctx.udp.send(hello, ctx.server_addr);
    std::cout << "[Handshake] Sending public key + IP..." << std::endl;
}

void handle_udp_event(ClientContext& ctx) {
    uint8_t buf[4096];
    NetAddress sender;
    ssize_t len = ctx.udp.receive(buf, sender);
    if (len <= 0) return;

    if (buf[0] == std::to_underlying(PacketType::Handshake) && !ctx.handshaked) {
        if (len < 33) return;
        std::vector<uint8_t> srv_pub(buf + 1, buf + 33);
        auto shared = CryptoEngine::derive_shared_secret(ctx.my_priv, srv_pub);
        ctx.crypto = std::make_unique<CryptoEngine>(shared);
        ctx.handshaked = true;
        std::cout << "[Handshake] SUCCESS! Encryption established." << std::endl;
    }
    else if (buf[0] == std::to_underlying(PacketType::Data) && ctx.handshaked) {
        // Здесь CryptoEngine::decrypt сам отрежет мусор (Padding), так как мы обновили его вчера
        auto decrypted = ctx.crypto->decrypt({buf + 1, static_cast<size_t>(len - 1)});
        ctx.tun.write_packet(decrypted);
    }
}

//CryptoEngine::encrypt will automatically add garbage up to 1400 bytes
void handle_tun_event(ClientContext& ctx) {
    ctx.tun.read_all_packets([&ctx](std::span<const uint8_t> packet) {
        auto encrypted = ctx.crypto->encrypt(packet);
        std::vector final_pkt = { std::to_underlying(PacketType::Data) };
        final_pkt.insert(final_pkt.end(), encrypted.begin(), encrypted.end());
        ctx.udp.send(final_pkt, ctx.server_addr);
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

        std::vector<uint8_t> my_priv, my_pub;
        CryptoEngine::generate_ecdh_keys(my_priv, my_pub);

        std::unique_ptr<CryptoEngine> crypto;
        bool handshaked = false;

        tun->up(v_ip_str, "255.255.255.0");
        if (const std::string mtu_cmd = std::format("ip link set dev {} mtu 1400", if_name); system(mtu_cmd.c_str()) != 0) {
             std::cerr << "[Warning] Failed to set MTU" << std::endl;
        }

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
            if (auto now = std::chrono::steady_clock::now();
                !handshaked && std::chrono::duration_cast<std::chrono::seconds>(now - last_hello).count() >= 2) {
                send_handshake(c_ctx, v_ip_str);
                last_hello = now;
            }

            int nfds = engine.wait(event_buffer, 100);
            for (int n = 0; n < nfds; ++n) {
                const auto* ctx = static_cast<const EventContext*>(event_buffer[n].data.ptr);
                if (ctx->fd == udp->get_fd()) {
                    handle_udp_event(c_ctx);
                }
                else if (ctx->fd == tun->get_fd() && handshaked) {
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