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
#include <string>
#include <stdexcept>
#include <openssl/evp.h>


class CryptoException : public std::runtime_error {
public:
 using std::runtime_error::runtime_error;
};

class CryptoEngine {
public:
 static constexpr size_t KEY_SIZE = 32;
 static constexpr size_t IV_SIZE = 12;
 static constexpr size_t TAG_SIZE = 16;
 static constexpr size_t TARGET_PACKET_SIZE = 1400;

 explicit CryptoEngine(const std::vector<uint8_t>& key);
 ~CryptoEngine();

 // Disable copying to protect keys in memory
 CryptoEngine(const CryptoEngine&) = delete;
 CryptoEngine& operator=(const CryptoEngine&) = delete;
 CryptoEngine(CryptoEngine&& other) noexcept;
 CryptoEngine& operator=(CryptoEngine&& other) noexcept;

 static void generate_ecdh_keys(std::vector<uint8_t>& priv_out, std::vector<uint8_t>& pub_out);
 static std::vector<uint8_t> derive_shared_secret(const std::vector<uint8_t>& my_priv,
                                                 const std::vector<uint8_t>& peer_pub);

 // External methods (now they do encryption + obfuscation)
 std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext);
 std::vector<uint8_t> decrypt(std::span<const uint8_t> ciphertext);

private:
 // Internal methods (pure OpenSSL encryption only)
 std::vector<uint8_t> encrypt_internal(std::span<const uint8_t> plaintext);
 std::vector<uint8_t> decrypt_internal(std::span<const uint8_t> ciphertext);

 std::vector<uint8_t> _key;
 EVP_CIPHER_CTX* _ctx;
};