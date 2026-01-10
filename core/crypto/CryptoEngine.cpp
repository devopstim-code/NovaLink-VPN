#include "CryptoEngine.hpp"
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <cstring>

extern "C" {
#include <oqs/oqs.h>
}

CryptoEngine::CryptoEngine(const std::vector<std::byte>& raw_shared_secret)
    : _ctx(EVP_CIPHER_CTX_new()) {
    if (!_ctx) throw CryptoException("EVP_CIPHER_CTX_new failed");
    _key = perform_hkdf(raw_shared_secret);
}

CryptoEngine::~CryptoEngine() {
    if (_ctx) EVP_CIPHER_CTX_free(_ctx);
    if (!_key.empty()) {
        OPENSSL_cleanse(_key.data(), _key.size());
    }
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

std::vector<std::byte> CryptoEngine::perform_hkdf(std::span<const std::byte> secret) {
    std::vector<std::byte> derived(32);
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!kctx) throw CryptoException("HKDF context allocation failed");

    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", (void*)secret.data(), secret.size()),
        OSSL_PARAM_construct_octet_string("salt", (void*)"NovaLink-PQ-v1", 14),
        OSSL_PARAM_construct_octet_string("info", (void*)"Session-Key", 11),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, reinterpret_cast<unsigned char*>(derived.data()), derived.size(), params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        throw CryptoException("HKDF derivation failed");
    }

    EVP_KDF_CTX_free(kctx);
    return derived;
}

void CryptoEngine::encrypt_inplace(std::span<std::byte> buffer, size_t data_offset, size_t data_len, size_t& out_len) {
    unsigned char* iv_ptr = reinterpret_cast<unsigned char*>(buffer.data() + data_offset - IV_SIZE);
    unsigned char* data_ptr = reinterpret_cast<unsigned char*>(buffer.data() + data_offset);

    if (RAND_bytes(iv_ptr, IV_SIZE) != 1) throw CryptoException("RAND_bytes failed");

    EVP_CIPHER_CTX_reset(_ctx);

    if (EVP_EncryptInit_ex(_ctx, EVP_chacha20_poly1305(), nullptr,
                           reinterpret_cast<const unsigned char*>(_key.data()), iv_ptr) != 1)
        throw CryptoException("EVP_EncryptInit failed");

    int len = 0;
    EVP_EncryptUpdate(_ctx, data_ptr, &len, data_ptr, static_cast<int>(data_len));

    int final_len = 0;
    EVP_EncryptFinal_ex(_ctx, data_ptr + len, &final_len);
    if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, data_ptr + data_len) != 1)
        throw CryptoException("Failed to get AEAD tag");

    out_len = IV_SIZE + data_len + TAG_SIZE;
}
bool CryptoEngine::decrypt_inplace(std::span<std::byte> buffer, size_t packet_offset, size_t packet_len, size_t& data_out_len) {
    if (packet_len < IV_SIZE + TAG_SIZE) return false;

    unsigned char* iv_ptr = reinterpret_cast<unsigned char*>(buffer.data() + packet_offset);
    unsigned char* cipher_ptr = iv_ptr + IV_SIZE;
    size_t cipher_len = packet_len - IV_SIZE - TAG_SIZE;
    unsigned char* tag_ptr = cipher_ptr + cipher_len;

    EVP_CIPHER_CTX_reset(_ctx);

    if (EVP_DecryptInit_ex(_ctx, EVP_chacha20_poly1305(), nullptr,
                           reinterpret_cast<const unsigned char*>(_key.data()), iv_ptr) != 1)
        return false;

    int len = 0;
    if (EVP_DecryptUpdate(_ctx, cipher_ptr, &len, cipher_ptr, static_cast<int>(cipher_len)) != 1)
        return false;
    if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag_ptr) != 1)
        return false;

    int outl = 0;
    if (EVP_DecryptFinal_ex(_ctx, cipher_ptr + len, &outl) <= 0) return false;

    data_out_len = cipher_len;
    return true;
}

void CryptoEngine::generate_ecdh_keys(std::vector<std::byte>& priv_out, std::vector<std::byte>& pub_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* pkey = nullptr;

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        throw CryptoException("X25519 keygen failed");
    }

    size_t len = 32;
    priv_out.resize(len); pub_out.resize(len);
    EVP_PKEY_get_raw_private_key(pkey, reinterpret_cast<uint8_t*>(priv_out.data()), &len);
    EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<uint8_t*>(pub_out.data()), &len);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

std::vector<std::byte> CryptoEngine::derive_shared_secret(const std::vector<std::byte>& my_priv, const std::vector<std::byte>& peer_pub) {
    auto* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, reinterpret_cast<const uint8_t*>(my_priv.data()), 32);
    auto* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, reinterpret_cast<const uint8_t*>(peer_pub.data()), 32);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);

    size_t len;
    EVP_PKEY_derive(ctx, nullptr, &len);
    std::vector<std::byte> secret(len);
    EVP_PKEY_derive(ctx, reinterpret_cast<uint8_t*>(secret.data()), &len);

    EVP_PKEY_free(priv); EVP_PKEY_free(peer); EVP_PKEY_CTX_free(ctx);
    return secret;
}


void CryptoEngine::generate_kyber_keys(std::vector<std::byte>& priv_out, std::vector<std::byte>& pub_out) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) throw CryptoException("Kyber-768 init failed");

    priv_out.resize(kem->length_secret_key);
    pub_out.resize(kem->length_public_key);

    if (OQS_KEM_keypair(kem, reinterpret_cast<uint8_t*>(pub_out.data()), reinterpret_cast<uint8_t*>(priv_out.data())) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw CryptoException("Kyber keygen failed");
    }
    OQS_KEM_free(kem);
}

std::pair<std::vector<std::byte>, std::vector<std::byte>> CryptoEngine::kyber_encapsulate(const std::vector<std::byte>& client_pub) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    std::vector<std::byte> ct(kem->length_ciphertext);
    std::vector<std::byte> ss(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, reinterpret_cast<uint8_t*>(ct.data()), reinterpret_cast<uint8_t*>(ss.data()),
                       reinterpret_cast<const uint8_t*>(client_pub.data())) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw CryptoException("Kyber encapsulate failed");
    }
    OQS_KEM_free(kem);
    return {ct, ss};
}

std::vector<std::byte> CryptoEngine::kyber_decapsulate(std::span<const std::byte> ciphertext, std::span<const std::byte> my_priv) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) throw CryptoException("Kyber init failed");
    std::vector<std::byte> ss(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(ss.data()),
                       reinterpret_cast<const uint8_t*>(ciphertext.data()),
                       reinterpret_cast<const uint8_t*>(my_priv.data())) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw CryptoException("Kyber decapsulate failed");
    }

    OQS_KEM_free(kem);
    return ss;
}