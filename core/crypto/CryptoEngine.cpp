#include "CryptoEngine.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <algorithm>
#include <cstring>


CryptoEngine::CryptoEngine(const std::vector<std::byte>& key)
    : _key(key), _ctx(EVP_CIPHER_CTX_new()) {
    if (_ctx == nullptr) {
        throw CryptoException("Failed to create EVP_CIPHER_CTX");
    }
}

CryptoEngine::~CryptoEngine() {
    if (_ctx != nullptr) {
        EVP_CIPHER_CTX_free(_ctx);
    }
}

CryptoEngine::CryptoEngine(CryptoEngine&& other) noexcept
    : _key(std::move(other._key)), _ctx(other._ctx) {
    other._ctx = nullptr;
}

CryptoEngine& CryptoEngine::operator=(CryptoEngine&& other) noexcept {
    if (this != &other) {
        if (_ctx != nullptr) {
            EVP_CIPHER_CTX_free(_ctx);
        }
        _key = std::move(other._key);
        _ctx = other._ctx;
        other._ctx = nullptr;
    }
    return *this;
}

// --- Static ECDH methods (X25519) ---

void CryptoEngine::generate_ecdh_keys(std::vector<std::byte>& priv_out, std::vector<std::byte>& pub_out) {
    auto* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* pkey = nullptr;

    if (ctx == nullptr || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to generate X25519 keys");
    }

    size_t priv_len = 32;
    priv_out.resize(priv_len);
    EVP_PKEY_get_raw_private_key(pkey, reinterpret_cast<unsigned char*>(priv_out.data()), &priv_len);

    size_t pub_len = 32;
    pub_out.resize(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char*>(pub_out.data()), &pub_len);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

std::vector<std::byte> CryptoEngine::derive_shared_secret(const std::vector<std::byte>& my_priv, const std::vector<std::byte>& peer_pub) {
    if (my_priv.size() != 32 || peer_pub.size() != 32) {
        throw CryptoException("Invalid key sizes for X25519");
    }

    auto* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(my_priv.data()), my_priv.size());
    auto* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(peer_pub.data()), peer_pub.size());

    if (priv_key == nullptr || peer_key == nullptr) {
        if (priv_key != nullptr) EVP_PKEY_free(priv_key);
        if (peer_key != nullptr) EVP_PKEY_free(peer_key);
        throw CryptoException("Failed to load keys for derivation");
    }

    auto* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (ctx == nullptr || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_key);
        throw CryptoException("ECDH derivation init failed");
    }

    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    std::vector<std::byte> secret(secret_len);
    EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char*>(secret.data()), &secret_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);

    return secret;
}

// --- External Methods with Obfuscation (Padding) ---

std::vector<std::byte> CryptoEngine::encrypt(std::span<const std::byte> plaintext) {
    auto encrypted = encrypt_internal(plaintext);
    if (encrypted.size() + 2 > TARGET_PACKET_SIZE) {
        return encrypted;
    }

    const auto padding_len = TARGET_PACKET_SIZE - encrypted.size() - 2;
    std::vector<std::byte> final_pkt = encrypted;
    final_pkt.resize(TARGET_PACKET_SIZE);

    RAND_bytes(reinterpret_cast<unsigned char*>(final_pkt.data() + encrypted.size()), static_cast<int>(padding_len));

    const auto enc_size = static_cast<uint16_t>(encrypted.size());
    final_pkt[TARGET_PACKET_SIZE - 2] = static_cast<std::byte>(enc_size & 0xFF);
    final_pkt[TARGET_PACKET_SIZE - 1] = static_cast<std::byte>((enc_size >> 8) & 0xFF);

    return final_pkt;
}

std::vector<std::byte> CryptoEngine::decrypt(std::span<const std::byte> ciphertext) {
    if (ciphertext.size() != TARGET_PACKET_SIZE) {
        return decrypt_internal(ciphertext);
    }

    const auto b1 = static_cast<uint16_t>(ciphertext[TARGET_PACKET_SIZE - 2]);
    const auto b2 = static_cast<uint16_t>(ciphertext[TARGET_PACKET_SIZE - 1]);
    const uint16_t real_size = b1 | (b2 << 8);

    if (real_size > TARGET_PACKET_SIZE - 2) {
        throw CryptoException("Invalid padding or corrupted packet");
    }

    return decrypt_internal(ciphertext.subspan(0, real_size));
}

// --- Internal encryption (AEAD: ChaCha20-Poly1305) ---

std::vector<std::byte> CryptoEngine::encrypt_internal(std::span<const std::byte> plaintext) {
    std::vector<std::byte> iv(IV_SIZE);
    RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), IV_SIZE);

    std::vector<std::byte> ciphertext(plaintext.size());
    int len = 0;
    uint8_t tag[TAG_SIZE];

    if (EVP_EncryptInit_ex(_ctx, EVP_chacha20_poly1305(), nullptr,
        reinterpret_cast<const unsigned char*>(_key.data()),
        reinterpret_cast<const unsigned char*>(iv.data())) <= 0) {
        throw CryptoException("Encryption init failed");
    }

    EVP_EncryptUpdate(_ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size()));

    int final_len = 0;
    EVP_EncryptFinal_ex(_ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &final_len);
    EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag);

    std::vector<std::byte> result;
    result.reserve(IV_SIZE + ciphertext.size() + TAG_SIZE);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    const auto* tag_ptr = reinterpret_cast<const std::byte*>(tag);
    result.insert(result.end(), tag_ptr, tag_ptr + TAG_SIZE);
    return result;
}

std::vector<std::byte> CryptoEngine::decrypt_internal(std::span<const std::byte> ciphertext) {
    if (ciphertext.size() < IV_SIZE + TAG_SIZE) {
        throw CryptoException("Ciphertext too short");
    }

    const auto* raw_ptr = reinterpret_cast<const unsigned char*>(ciphertext.data());
    const auto body_len = ciphertext.size() - IV_SIZE - TAG_SIZE;
    const auto* actual_cipher = raw_ptr + IV_SIZE;
    const auto* tag_ptr = actual_cipher + body_len;

    std::vector<std::byte> plaintext(body_len);
    int len = 0;

    if (EVP_DecryptInit_ex(_ctx, EVP_chacha20_poly1305(), nullptr,
        reinterpret_cast<const unsigned char*>(_key.data()), raw_ptr) <= 0) {
        throw CryptoException("Decryption init failed");
    }

    auto* out_ptr = reinterpret_cast<unsigned char*>(plaintext.data());
    EVP_DecryptUpdate(_ctx, out_ptr, &len, actual_cipher, static_cast<int>(body_len));

    uint8_t tag_buffer[TAG_SIZE];
    std::memcpy(tag_buffer, tag_ptr, TAG_SIZE);
    EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag_buffer);

    int outl = 0;
    if (::EVP_DecryptFinal_ex(_ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &outl) <= 0) {
        throw CryptoException("Decryption integrity check failed (MAC mismatch)");
    }

    return plaintext;
}