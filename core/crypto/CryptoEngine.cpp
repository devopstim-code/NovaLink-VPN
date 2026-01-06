#include "CryptoEngine.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdexcept>

// Constructor: Initialize the context for data encryption
CryptoEngine::CryptoEngine(const std::vector<uint8_t>& key) : _key(key) {
    if (key.size() != KEY_SIZE) {
        throw std::runtime_error("AES-256 key must be 32 bytes");
    }
    _ctx = EVP_CIPHER_CTX_new();
    if (!_ctx) throw std::runtime_error("Failed to create EVP context");
}

CryptoEngine::~CryptoEngine() {
    if (_ctx) EVP_CIPHER_CTX_free(_ctx);
}

// Data Packet Encryption
std::vector<uint8_t> CryptoEngine::encrypt(std::span<const uint8_t> plaintext) {
    std::vector<uint8_t> out(IV_SIZE + plaintext.size() + TAG_SIZE);
    uint8_t* iv = out.data();
    uint8_t* ciphertext = out.data() + IV_SIZE;
    uint8_t* tag = out.data() + IV_SIZE + plaintext.size();

    if (RAND_bytes(iv, IV_SIZE) != 1) throw std::runtime_error("RAND_bytes failed");

    int len;
    if (EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv) != 1)
        throw std::runtime_error("EncryptInit failed");

    if (EVP_EncryptUpdate(_ctx, ciphertext, &len, plaintext.data(), (int)plaintext.size()) != 1)
        throw std::runtime_error("EncryptUpdate failed");

    if (EVP_EncryptFinal_ex(_ctx, ciphertext + len, &len) != 1)
        throw std::runtime_error("EncryptFinal failed");

    if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
        throw std::runtime_error("Get TAG failed");

    return out;
}

// Data decryption
std::vector<uint8_t> CryptoEngine::decrypt(std::span<const uint8_t> data) {
    if (data.size() < IV_SIZE + TAG_SIZE) throw std::runtime_error("Packet too short");

    size_t cipher_len = data.size() - IV_SIZE - TAG_SIZE;
    std::vector<uint8_t> plaintext(cipher_len);

    const uint8_t* iv = data.data();
    const uint8_t* ciphertext = data.data() + IV_SIZE;
    const uint8_t* tag = data.data() + IV_SIZE + cipher_len;

    int len;
    if (EVP_DecryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv) != 1)
        throw std::runtime_error("DecryptInit failed");

    if (EVP_DecryptUpdate(_ctx, plaintext.data(), &len, ciphertext, (int)cipher_len) != 1)
        throw std::runtime_error("DecryptUpdate failed");

    if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1)
        throw std::runtime_error("Set TAG failed");

    if (EVP_DecryptFinal_ex(_ctx, plaintext.data() + len, &len) <= 0) {
        throw std::runtime_error("Integrity check failed (Bad Tag)");
    }

    return plaintext;
}

//   STATIC METHODS FOR HANDSHAKE (Curve25519)

void CryptoEngine::generate_ecdh_keys(std::vector<uint8_t>& priv_out, std::vector<uint8_t>& pub_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0) throw std::runtime_error("Keygen init failed");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throw std::runtime_error("Keygen failed");

    size_t len = 32;
    priv_out.resize(len);
    pub_out.resize(len);

    EVP_PKEY_get_raw_private_key(pkey, priv_out.data(), &len);
    EVP_PKEY_get_raw_public_key(pkey, pub_out.data(), &len);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

std::vector<uint8_t> CryptoEngine::derive_shared_secret(const std::vector<uint8_t>& my_priv,
                                                       const std::vector<uint8_t>& peer_pub) {
    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_priv.data(), 32);
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), 32);

    if (!priv_key || !peer_key) throw std::runtime_error("Failed to load raw keys");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_key);

    size_t secret_len;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);

    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(ctx);

    return secret;
}