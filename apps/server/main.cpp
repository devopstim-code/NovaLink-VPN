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
#include <cstring>
#include <unordered_map>
#include <chrono>
#include <arpa/inet.h>

std::atomic<bool> global_running{true};
void signal_handler(int sig) { global_running.store(false); }

enum PacketType : uint8_t { PACKET_HANDSHAKE = 0x01, PACKET_DATA = 0x02 };

std::string address_to_key(const NetAddress& addr) {
    char ip_str[INET_ADDRSTRLEN];
    auto* saddr = (struct sockaddr_in*)&addr.storage;
    inet_ntop(AF_INET, &(saddr->sin_addr), ip_str, INET_ADDRSTRLEN);
    return std::string(ip_str) + ":" + std::to_string(ntohs(saddr->sin_port));
}

struct ClientSession {
    std::unique_ptr<CryptoEngine> crypto;
    NetAddress address;
    uint32_t internal_ip;
    std::chrono::steady_clock::time_point last_seen;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <listen_port>" << std::endl;
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::unordered_map<std::string, std::shared_ptr<ClientSession>> sessions;
    std::unordered_map<uint32_t, std::shared_ptr<ClientSession>> route_table;

    try {
        uint16_t listen_port = static_cast<uint16_t>(std::stoi(argv[1]));
        auto tun = std::make_unique<TunDevice>("nova_srv");
        auto udp = std::make_unique<UdpSocket>(AF_INET);
        udp->bind(listen_port);

        std::vector<uint8_t> srv_priv, srv_pub;
        CryptoEngine::generate_ecdh_keys(srv_priv, srv_pub);

        tun->up("10.8.0.1", "255.255.255.0");
        system("ip link set dev nova_srv mtu 1400");

        EpollEngine engine;
        EventContext tun_ctx{tun->get_fd(), tun.get(), 0};
        EventContext udp_ctx{udp->get_fd(), udp.get(), 0};
        engine.add(tun->get_fd(), EPOLLIN, &tun_ctx);
        engine.add(udp->get_fd(), EPOLLIN, &udp_ctx);

        std::cout << "[NovaLink Server] Started on port " << listen_port << std::endl;
        std::vector<epoll_event> event_buffer(16);

        while (global_running.load()) {
            int nfds = engine.wait(event_buffer, 100);
            for (int n = 0; n < nfds; ++n) {
                auto* ctx = static_cast<EventContext*>(event_buffer[n].data.ptr);

                if (ctx->fd == udp->get_fd()) {
                    uint8_t buf[4096];
                    NetAddress sender;
                    ssize_t len = udp->receive(buf, sender);
                    if (len <= 0) continue;

                    // SINGLE HANDSHAKE BLOCK
                    if (buf[0] == PACKET_HANDSHAKE) {
                        if (len < 37) continue;

                        std::vector<uint8_t> client_pub(buf + 1, buf + 33);
                        uint32_t requested_ip;
                        std::memcpy(&requested_ip, buf + 33, 4);

                        auto shared = CryptoEngine::derive_shared_secret(srv_priv, client_pub);
                        auto session = std::make_shared<ClientSession>();
                        session->crypto = std::make_unique<CryptoEngine>(shared);
                        session->address = sender;
                        session->internal_ip = requested_ip;
                        session->last_seen = std::chrono::steady_clock::now();

                        sessions[address_to_key(sender)] = session;
                        route_table[requested_ip] = session;

                        std::vector<uint8_t> answer = { PACKET_HANDSHAKE };
                        answer.insert(answer.end(), srv_pub.begin(), srv_pub.end());
                        udp->send(answer, sender);

                        struct in_addr addr_struct;
                        addr_struct.s_addr = requested_ip;
                        std::cout << "[Handshake] Registered " << address_to_key(sender)
                                  << " as " << inet_ntoa(addr_struct) << std::endl;
                    }
                    else if (buf[0] == PACKET_DATA) {
                        auto it = sessions.find(address_to_key(sender));
                        if (it != sessions.end()) {
                            try {
                                auto decrypted = it->second->crypto->decrypt({buf + 1, (size_t)len - 1});
                                tun->write_packet(decrypted);
                                it->second->last_seen = std::chrono::steady_clock::now();
                            } catch (...) { /* Decrypt error */ }
                        }
                    }
                }
                else if (ctx->fd == tun->get_fd()) {
                    tun->read_all_packets([&](std::span<const uint8_t> packet) {
                        if (packet.size() < 20) return;

                        // Reading the Destination IP from the IP header (bytes 16-19)
                        uint32_t dest_ip;
                        std::memcpy(&dest_ip, packet.data() + 16, 4);

                        auto it = route_table.find(dest_ip);
                        if (it != route_table.end()) {
                            try {
                                auto encrypted = it->second->crypto->encrypt(packet);
                                std::vector<uint8_t> final_pkt = { PACKET_DATA };
                                final_pkt.insert(final_pkt.end(), encrypted.begin(), encrypted.end());
                                udp->send(final_pkt, it->second->address);
                            } catch (...) {}
                        }
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