#include "CryptoEngine.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <algorithm>
#include <cstring>

//Constructor and Destructor
CryptoEngine::CryptoEngine(const std::vector<uint8_t>& key)
    : _key(key), _ctx(EVP_CIPHER_CTX_new()) {
    if (!_ctx) throw CryptoException("Failed to create EVP_CIPHER_CTX");
}

CryptoEngine::~CryptoEngine() {
    if (_ctx) EVP_CIPHER_CTX_free(_ctx);
}

CryptoEngine::CryptoEngine(CryptoEngine&& other) noexcept
    : _key(std::move(other._key)), _ctx(other._ctx) {
    other._ctx = nullptr;
}

CryptoEngine& CryptoEngine::operator=(CryptoEngine&& other) noexcept {
    if (this != &other) {
        if (_ctx) EVP_CIPHER_CTX_free(_ctx);
        _key = std::move(other._key);
        _ctx = other._ctx;
        other._ctx = nullptr;
    }
    return *this;
}

                //Static ECDH methods

void CryptoEngine::generate_ecdh_keys(std::vector<uint8_t>& priv_out, std::vector<uint8_t>& pub_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* pkey = nullptr;

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to generate X25519 keys");
    }

    size_t priv_len = 32;
    priv_out.resize(priv_len);
    EVP_PKEY_get_raw_private_key(pkey, priv_out.data(), &priv_len);

    size_t pub_len = 32;
    pub_out.resize(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_out.data(), &pub_len);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

std::vector<uint8_t> CryptoEngine::derive_shared_secret(const std::vector<uint8_t>& my_priv, const std::vector<uint8_t>& peer_pub) {
    if (my_priv.size() != 32 || peer_pub.size() != 32) {
        throw CryptoException("Invalid key sizes for X25519");
    }

    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_priv.data(), my_priv.size());
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());

    if (!priv_key || !peer_key) {
        if (priv_key) EVP_PKEY_free(priv_key);
        if (peer_key) EVP_PKEY_free(peer_key);
        throw CryptoException("Failed to load keys for derivation");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_key);
        throw CryptoException("ECDH derivation init failed");
    }

    size_t secret_len;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);

    return secret;
}

// External Methods with Obfuscation (Padding)

std::vector<uint8_t> CryptoEngine::encrypt(std::span<const uint8_t> plaintext) {
    std::vector<uint8_t> encrypted = encrypt_internal(plaintext);
    if (encrypted.size() + 2 > TARGET_PACKET_SIZE) return encrypted;

    size_t padding_len = TARGET_PACKET_SIZE - encrypted.size() - 2;
    std::vector<uint8_t> final_pkt = encrypted;
    final_pkt.resize(TARGET_PACKET_SIZE);

    RAND_bytes(final_pkt.data() + encrypted.size(), static_cast<int>(padding_len));

    uint16_t enc_size = static_cast<uint16_t>(encrypted.size());
    final_pkt[TARGET_PACKET_SIZE - 2] = static_cast<uint8_t>(enc_size & 0xFF);
    final_pkt[TARGET_PACKET_SIZE - 1] = static_cast<uint8_t>((enc_size >> 8) & 0xFF);

    return final_pkt;
}

std::vector<uint8_t> CryptoEngine::decrypt(std::span<const uint8_t> ciphertext) {
    if (ciphertext.size() != TARGET_PACKET_SIZE) {
        return decrypt_internal(ciphertext);
    }
    uint16_t real_size = ciphertext[TARGET_PACKET_SIZE - 2] | (ciphertext[TARGET_PACKET_SIZE - 1] << 8);

    if (real_size > TARGET_PACKET_SIZE - 2) {
        throw CryptoException("Invalid padding or corrupted packet");
    }

    return decrypt_internal(ciphertext.subspan(0, real_size));
}

// Internal encryption (AEAD: ChaCha20-Poly1305)

std::vector<uint8_t> CryptoEngine::encrypt_internal(std::span<const uint8_t> plaintext) {
    std::vector<uint8_t> iv(IV_SIZE);
    RAND_bytes(iv.data(), IV_SIZE);

    std::vector<uint8_t> ciphertext(plaintext.size());
    int len = 0;
    uint8_t tag[TAG_SIZE];

    if (EVP_EncryptInit_ex(_ctx, EVP_chacha20_poly1305(), nullptr, _key.data(), iv.data()) <= 0)
        throw CryptoException("Encryption init failed");

    EVP_EncryptUpdate(_ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()));
    EVP_EncryptFinal_ex(_ctx, ciphertext.data() + len, &len);
    EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag);

    std::vector<uint8_t> result;
    result.reserve(IV_SIZE + ciphertext.size() + TAG_SIZE);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag, tag + TAG_SIZE);
    return result;
}

std::vector<uint8_t> CryptoEngine::decrypt_internal(std::span<const uint8_t> ciphertext) {
    if (ciphertext.size() < IV_SIZE + TAG_SIZE)
        throw CryptoException("Ciphertext too short");

    const uint8_t* iv = ciphertext.data();
    size_t body_len = ciphertext.size() - IV_SIZE - TAG_SIZE;
    const uint8_t* actual_cipher = ciphertext.data() + IV_SIZE;
    const uint8_t* tag = ciphertext.data() + IV_SIZE + body_len;

    std::vector<uint8_t> plaintext(body_len);
    int len = 0;

    if (EVP_DecryptInit_ex(_ctx, EVP_chacha20_poly1305(), nullptr, _key.data(), iv) <= 0)
        throw CryptoException("Decryption init failed");

    EVP_DecryptUpdate(_ctx, plaintext.data(), &len, actual_cipher, static_cast<int>(body_len));
    EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, const_cast<uint8_t*>(tag));

    if (EVP_DecryptFinal_ex(_ctx, plaintext.data() + len, &len) <= 0) {
        throw CryptoException("Integrity check failed: packet corrupted or wrong key");
    }

    return plaintext;
}