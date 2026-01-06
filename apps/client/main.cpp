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

void send_handshake(UdpSocket* udp, const NetAddress& server_addr, const std::vector<uint8_t>& my_pub, const std::string& v_ip_str) {
    // Sonar: std::to_underlying (C++23) вместо static_cast
    std::vector hello = { std::to_underlying(PacketType::Handshake) };
    hello.insert(hello.end(), my_pub.begin(), my_pub.end());

    uint32_t my_v_ip = inet_addr(v_ip_str.c_str());
    // Sonar: Используем reinterpret_cast аккуратно (указатель на байты)
    auto* ip_ptr = reinterpret_cast<uint8_t*>(&my_v_ip);
    hello.insert(hello.end(), ip_ptr, ip_ptr + 4);

    udp->send(hello, server_addr);
    std::cout << "[Handshake] Sending public key + IP..." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <virtual_ip>" << std::endl;
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        const std::string server_ip = argv[1];
        const auto server_port = static_cast<uint16_t>(std::stoi(argv[2]));
        const std::string v_ip_str = argv[3];
        const std::string if_name = "nova1";

        auto tun = std::make_unique<TunDevice>(if_name);
        auto udp = std::make_unique<UdpSocket>(AF_INET);
        NetAddress server_addr(server_ip, server_port);

        std::vector<uint8_t> my_priv;
        std::vector<uint8_t> my_pub;
        CryptoEngine::generate_ecdh_keys(my_priv, my_pub);

        std::unique_ptr<CryptoEngine> crypto;
        bool handshaked = false;

        tun->up(v_ip_str, "255.255.255.0");

        // Sonar: Используем init-statement в if для mtu_cmd
        if (const std::string mtu_cmd = "ip link set dev " + if_name + " mtu 1400"; system(mtu_cmd.c_str()) != 0) {
             std::cerr << "[Warning] Failed to set MTU" << std::endl;
        }

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};
        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        std::cout << "[NovaLink] Client " << v_ip_str << " started." << std::endl;

        std::vector<epoll_event> event_buffer(16);
        auto last_hello = std::chrono::steady_clock::now();

        while (global_running.load()) {
            // Sonar: Init-statement для "now" внутри if
            if (auto now = std::chrono::steady_clock::now();
                !handshaked && std::chrono::duration_cast<std::chrono::seconds>(now - last_hello).count() >= 2) {
                send_handshake(udp.get(), server_addr, my_pub, v_ip_str);
                last_hello = now;
            }

            int nfds = engine.wait(event_buffer, 100);
            for (int n = 0; n < nfds; ++n) {
                auto* ctx = static_cast<EventContext*>(event_buffer[n].data.ptr);

                if (ctx->fd == udp->get_fd()) {
                    uint8_t buf[4096];
                    NetAddress sender;
                    ssize_t len = udp->receive(buf, sender);
                    if (len <= 0) continue;

                    // Sonar: Используем std::to_underlying
                    if (buf[0] == std::to_underlying(PacketType::Handshake) && !handshaked) {
                        if (len < 33) continue;
                        std::vector<uint8_t> srv_pub(buf + 1, buf + 33);
                        auto shared = CryptoEngine::derive_shared_secret(my_priv, srv_pub);
                        crypto = std::make_unique<CryptoEngine>(shared);
                        handshaked = true;
                        std::cout << "[Handshake] SUCCESS!" << std::endl;
                    }
                    else if (buf[0] == std::to_underlying(PacketType::Data) && handshaked) {
                        auto decrypted = crypto->decrypt({buf + 1, static_cast<size_t>(len - 1)});
                        tun->write_packet(decrypted);
                    }
                }
                else if (ctx->fd == tun->get_fd() && handshaked) {
                    tun->read_all_packets([&](std::span<const uint8_t> packet) {
                        auto encrypted = crypto->encrypt(packet);
                        // Sonar: std::to_underlying
                        std::vector final_pkt = { std::to_underlying(PacketType::Data) };
                        final_pkt.insert(final_pkt.end(), encrypted.begin(), encrypted.end());
                        udp->send(final_pkt, server_addr);
                    });
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[Critical] " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}