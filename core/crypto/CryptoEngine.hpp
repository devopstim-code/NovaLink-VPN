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
#include <openssl/evp.h>
#include <openssl/ec.h>

class CryptoEngine {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

    explicit CryptoEngine(const std::vector<uint8_t>& key);
    ~CryptoEngine();
    static void generate_ecdh_keys(std::vector<uint8_t>& priv_out, std::vector<uint8_t>& pub_out);
    static std::vector<uint8_t> derive_shared_secret(const std::vector<uint8_t>& my_priv,
                                                    const std::vector<uint8_t>& peer_pub);

    // Package format: [IV(12b)] + [Payload] + [Tag(16b)]
    std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext);
    std::vector<uint8_t> decrypt(std::span<const uint8_t> ciphertext);

private:
    std::vector<uint8_t> _key;
    EVP_CIPHER_CTX* _ctx;
};