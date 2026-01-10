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
#include <stdexcept>
#include <openssl/evp.h>
#include <span>
#include <oqs/oqs.h>
#include <memory>

class CryptoException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class CryptoEngine {
public:
    // Size constants (RFC standards and Kyber-768)
    static constexpr size_t IV_SIZE      = 12;
    static constexpr size_t TAG_SIZE     = 16;
    static constexpr size_t KYBER768_PUB    = 1184;
    static constexpr size_t KYBER768_PRIV   = 2400;
    static constexpr size_t KYBER768_CIPHER = 1088;
    static constexpr size_t KYBER768_SECRET = 32;

    explicit CryptoEngine(const std::vector<std::byte>& raw_shared_secret);
    ~CryptoEngine();
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;
    CryptoEngine(CryptoEngine&& other) noexcept;
    CryptoEngine& operator=(CryptoEngine&& other) noexcept;
    void encrypt_inplace(std::span<std::byte> buffer, size_t data_offset, size_t data_len, size_t& out_len);
    bool decrypt_inplace(std::span<std::byte> buffer, size_t packet_offset, size_t packet_len, size_t& data_out_len);

    static void generate_ecdh_keys(std::vector<std::byte>& priv_out, std::vector<std::byte>& pub_out);
    static std::vector<std::byte> derive_shared_secret(const std::vector<std::byte>& my_priv, const std::vector<std::byte>& peer_pub);
    static void generate_kyber_keys(std::vector<std::byte>& priv_out, std::vector<std::byte>& pub_out);
    static std::pair<std::vector<std::byte>, std::vector<std::byte>> kyber_encapsulate(const std::vector<std::byte>& client_pub);
    static std::vector<std::byte> kyber_decapsulate(std::span<const std::byte> ciphertext, std::span<const std::byte> my_priv);
    static std::pair<std::vector<std::byte>, std::vector<std::byte>> kyber_encapsulate(std::span<const std::byte> pub_key);
private:
    std::vector<std::byte> _key;
    EVP_CIPHER_CTX* _ctx;

    static std::vector<std::byte> perform_hkdf(std::span<const std::byte> secret);
};