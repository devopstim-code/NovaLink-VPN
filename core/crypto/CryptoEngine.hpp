/*****************************************************************//**
* \file   CryptoEngine.hpp
* \brief  Tunnel security.
* * Implements key exchange using the ECDH (Curve25519) protocol and
* symmetric packet encryption using AES-256-GCM.
* * \author Devopstim
* \date   2025-2026
* \project NovaLink Vpn
* * Copyright (c) 2025-2026 Devopstim. All rights reserved.
 *********************************************************************/
#pragma once

#include <vector>
#include <span>
#include <stdexcept>
#include <cstddef>


struct evp_cipher_ctx_st;
using EVP_CIPHER_CTX = struct evp_cipher_ctx_st;

class CryptoException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class CryptoEngine final {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t TARGET_PACKET_SIZE = 1400;

    explicit CryptoEngine(const std::vector<std::byte>& key);
    ~CryptoEngine();
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;
    CryptoEngine(CryptoEngine&& other) noexcept;
    CryptoEngine& operator=(CryptoEngine&& other) noexcept;

    static void generate_ecdh_keys(std::vector<std::byte>& priv_out, std::vector<std::byte>& pub_out);
    static std::vector<std::byte> derive_shared_secret(const std::vector<std::byte>& my_priv,
                                                      const std::vector<std::byte>& peer_pub);

    [[nodiscard]] std::vector<std::byte> encrypt(std::span<const std::byte> plaintext);
    [[nodiscard]] std::vector<std::byte> decrypt(std::span<const std::byte> ciphertext);

private:
    [[nodiscard]] std::vector<std::byte> encrypt_internal(std::span<const std::byte> plaintext);

    int EVP_DecryptFinal_ex(unsigned char * ctx, int * outm);

    [[nodiscard]] std::vector<std::byte> decrypt_internal(std::span<const std::byte> ciphertext);

    std::vector<std::byte> _key;

    EVP_CIPHER_CTX* _ctx = nullptr;
};