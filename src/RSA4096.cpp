#include "RSA4096.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <memory>
#include <stdexcept>

namespace nsg {
namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

std::string bioToString(BIO* bio) {
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio, &memory);
    if (memory == nullptr || memory->data == nullptr) {
        throw std::runtime_error("Failed to read PEM data.");
    }
    return std::string(memory->data, memory->length);
}

}

RSA4096::RSA4096() : key_(nullptr) {}

RSA4096::~RSA4096() {
    EVP_PKEY_free(key_);
}

RSA4096::RSA4096(RSA4096&& other) noexcept : key_(other.key_) {
    other.key_ = nullptr;
}

RSA4096& RSA4096::operator=(RSA4096&& other) noexcept {
    if (this != &other) {
        EVP_PKEY_free(key_);
        key_ = other.key_;
        other.key_ = nullptr;
    }
    return *this;
}

void RSA4096::replaceKey(EVP_PKEY* newKey) {
    EVP_PKEY_free(key_);
    key_ = newKey;
}

void RSA4096::generateKeyPair() {
    EVP_PKEY* generated = EVP_PKEY_Q_keygen(
        nullptr,
        nullptr,
        "RSA",
        static_cast<std::size_t>(4096));

    if (generated == nullptr) {
        throw std::runtime_error("Failed to generate RSA-4096 key pair.");
    }

    replaceKey(generated);
}

std::string RSA4096::publicKeyPEM() const {
    if (!key_) {
        throw std::runtime_error("RSA key is not loaded.");
    }

    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key_) != 1) {
        throw std::runtime_error("Failed to export RSA public key.");
    }

    return bioToString(bio.get());
}

std::string RSA4096::privateKeyPEM() const {
    if (!key_) {
        throw std::runtime_error("RSA key is not loaded.");
    }

    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(
                    bio.get(),
                    key_,
                    nullptr,
                    nullptr,
                    0,
                    nullptr,
                    nullptr) != 1) {
        throw std::runtime_error("Failed to export RSA private key.");
    }

    return bioToString(bio.get());
}

void RSA4096::loadPublicKeyPEM(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        throw std::runtime_error("Failed to create RSA public-key buffer.");
    }

    EVP_PKEY* loaded = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!loaded || EVP_PKEY_is_a(loaded, "RSA") != 1 || EVP_PKEY_get_bits(loaded) != 4096) {
        EVP_PKEY_free(loaded);
        throw std::runtime_error("Invalid RSA-4096 public key PEM.");
    }

    replaceKey(loaded);
}

void RSA4096::loadPrivateKeyPEM(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        throw std::runtime_error("Failed to create RSA private-key buffer.");
    }

    EVP_PKEY* loaded = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!loaded || EVP_PKEY_is_a(loaded, "RSA") != 1 || EVP_PKEY_get_bits(loaded) != 4096) {
        EVP_PKEY_free(loaded);
        throw std::runtime_error("Invalid RSA-4096 private key PEM.");
    }

    replaceKey(loaded);
}

RSA4096::ByteVector RSA4096::encrypt(const ByteVector& plaintext) const {
    if (!key_) {
        throw std::runtime_error("RSA key is not loaded.");
    }
    if (plaintext.size() > 446U) {
        throw std::runtime_error("RSA-4096 OAEP-SHA256 plaintext cannot exceed 446 bytes.");
    }

    PkeyContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key_, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize RSA encryption.");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error("Failed to configure RSA-OAEP-SHA256.");
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_encrypt(
            ctx.get(),
            nullptr,
            &outputLength,
            plaintext.data(),
            plaintext.size()) <= 0) {
        throw std::runtime_error("Failed to determine RSA ciphertext size.");
    }

    ByteVector ciphertext(outputLength);
    if (EVP_PKEY_encrypt(
            ctx.get(),
            ciphertext.data(),
            &outputLength,
            plaintext.data(),
            plaintext.size()) <= 0) {
        throw std::runtime_error("RSA encryption failed.");
    }

    ciphertext.resize(outputLength);
    return ciphertext;
}

RSA4096::ByteVector RSA4096::decrypt(const ByteVector& ciphertext) const {
    if (!key_) {
        throw std::runtime_error("RSA key is not loaded.");
    }

    PkeyContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key_, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize RSA decryption.");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error("Failed to configure RSA-OAEP-SHA256.");
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_decrypt(
            ctx.get(),
            nullptr,
            &outputLength,
            ciphertext.data(),
            ciphertext.size()) <= 0) {
        throw std::runtime_error("Failed to determine RSA plaintext size.");
    }

    ByteVector plaintext(outputLength);
    if (EVP_PKEY_decrypt(
            ctx.get(),
            plaintext.data(),
            &outputLength,
            ciphertext.data(),
            ciphertext.size()) <= 0) {
        throw std::runtime_error("RSA decryption failed.");
    }

    plaintext.resize(outputLength);
    return plaintext;
}

bool RSA4096::hasKey() const noexcept {
    return key_ != nullptr;
}

}
