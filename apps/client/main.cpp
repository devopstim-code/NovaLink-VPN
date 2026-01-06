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
#include <arpa/inet.h>

namespace {
    std::atomic<bool> global_running{true};
}
void signal_handler(int sig) { global_running.store(false); }

enum PacketType : uint8_t {
    PACKET_HANDSHAKE = 0x01,
    PACKET_DATA      = 0x02
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <virtual_ip>" << std::endl;
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        const std::string server_ip = argv[1];
        const uint16_t server_port = static_cast<uint16_t>(std::stoi(argv[2]));
        const std::string v_ip_str = argv[3];
        const std::string if_name = "nova1";

        auto tun = std::make_unique<TunDevice>(if_name);
        auto udp = std::make_unique<UdpSocket>(AF_INET);
        NetAddress server_addr(server_ip, server_port);

        std::vector<uint8_t> my_priv, my_pub;
        CryptoEngine::generate_ecdh_keys(my_priv, my_pub);

        std::unique_ptr<CryptoEngine> crypto;
        bool handshaked = false;

        // Settings TUN
        tun->up(v_ip_str, "255.255.255.0");
        std::string mtu_cmd = "ip link set dev " + if_name + " mtu 1400";
        system(mtu_cmd.c_str());

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};
        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        std::cout << "[NovaLink] Client " << v_ip_str << " started." << std::endl;

        std::vector<epoll_event> event_buffer(16);
        auto last_hello = std::chrono::steady_clock::now();

        while (global_running.load()) {
            // UNITED Handshake Block
            if (!handshaked) {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - last_hello).count() >= 2) {
                    std::vector<uint8_t> hello = { PACKET_HANDSHAKE };
                    hello.insert(hello.end(), my_pub.begin(), my_pub.end());

                    // We add our IP so that the server knows where to respond.
                    uint32_t my_v_ip = inet_addr(v_ip_str.c_str());
                    uint8_t* ip_ptr = (uint8_t*)&my_v_ip;
                    hello.insert(hello.end(), ip_ptr, ip_ptr + 4);

                    udp->send(hello, server_addr);
                    last_hello = now;
                    std::cout << "[Handshake] Sending public key + IP..." << std::endl;
                }
            }

            int nfds = engine.wait(event_buffer, 100);
            for (int n = 0; n < nfds; ++n) {
                auto* ctx = static_cast<EventContext*>(event_buffer[n].data.ptr);

                if (ctx->fd == udp->get_fd()) {
                    uint8_t buf[4096];
                    NetAddress sender;
                    ssize_t len = udp->receive(buf, sender);
                    if (len <= 0) continue;

                    if (buf[0] == PACKET_HANDSHAKE && !handshaked) {
                        if (len < 33) continue;
                        std::vector<uint8_t> srv_pub(buf + 1, buf + 33);
                        auto shared = CryptoEngine::derive_shared_secret(my_priv, srv_pub);
                        crypto = std::make_unique<CryptoEngine>(shared);
                        handshaked = true;
                        std::cout << "[Handshake] SUCCESS! Tunnel is encrypted." << std::endl;
                    }
                    else if (buf[0] == PACKET_DATA && handshaked) {
                        try {
                            auto decrypted = crypto->decrypt({buf + 1, (size_t)len - 1});
                            tun->write_packet(decrypted);
                        } catch (...) {}
                    }
                }
                else if (ctx->fd == tun->get_fd() && handshaked) {
                    tun->read_all_packets([&](std::span<const uint8_t> packet) {
                        try {
                            auto encrypted = crypto->encrypt(packet);
                            std::vector<uint8_t> final_pkt = { PACKET_DATA };
                            final_pkt.insert(final_pkt.end(), encrypted.begin(), encrypted.end());
                            udp->send(final_pkt, server_addr);
                        } catch (...) {}
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