#include "MLKEM1024.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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

MLKEM1024::MLKEM1024() : key_(nullptr) {}

MLKEM1024::~MLKEM1024() {
    EVP_PKEY_free(key_);
}

MLKEM1024::MLKEM1024(MLKEM1024&& other) noexcept : key_(other.key_) {
    other.key_ = nullptr;
}

MLKEM1024& MLKEM1024::operator=(MLKEM1024&& other) noexcept {
    if (this != &other) {
        EVP_PKEY_free(key_);
        key_ = other.key_;
        other.key_ = nullptr;
    }
    return *this;
}

void MLKEM1024::replaceKey(EVP_PKEY* newKey) {
    EVP_PKEY_free(key_);
    key_ = newKey;
}

void MLKEM1024::generateKeyPair() {
    EVP_PKEY* generated = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-1024");
    if (generated == nullptr) {
        throw std::runtime_error(
            "Failed to generate ML-KEM-1024 key pair. OpenSSL 3.5 or newer is required.");
    }
    replaceKey(generated);
}

std::string MLKEM1024::publicKeyPEM() const {
    if (!key_) {
        throw std::runtime_error("ML-KEM key is not loaded.");
    }

    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key_) != 1) {
        throw std::runtime_error("Failed to export ML-KEM public key.");
    }

    return bioToString(bio.get());
}

std::string MLKEM1024::privateKeyPEM() const {
    if (!key_) {
        throw std::runtime_error("ML-KEM key is not loaded.");
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
        throw std::runtime_error("Failed to export ML-KEM private key.");
    }

    return bioToString(bio.get());
}

void MLKEM1024::loadPublicKeyPEM(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        throw std::runtime_error("Failed to create ML-KEM public-key buffer.");
    }

    EVP_PKEY* loaded = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!loaded || EVP_PKEY_is_a(loaded, "ML-KEM-1024") != 1) {
        EVP_PKEY_free(loaded);
        throw std::runtime_error("Invalid ML-KEM-1024 public key PEM.");
    }

    replaceKey(loaded);
}

void MLKEM1024::loadPrivateKeyPEM(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        throw std::runtime_error("Failed to create ML-KEM private-key buffer.");
    }

    EVP_PKEY* loaded = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!loaded || EVP_PKEY_is_a(loaded, "ML-KEM-1024") != 1) {
        EVP_PKEY_free(loaded);
        throw std::runtime_error("Invalid ML-KEM-1024 private key PEM.");
    }

    replaceKey(loaded);
}

MLKEM1024::EncapsulationResult MLKEM1024::encapsulate() const {
    if (!key_) {
        throw std::runtime_error("ML-KEM key is not loaded.");
    }

    PkeyContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key_, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
        throw std::runtime_error("Failed to initialize ML-KEM encapsulation.");
    }

    std::size_t ciphertextLength = 0;
    std::size_t secretLength = 0;

    if (EVP_PKEY_encapsulate(
            ctx.get(),
            nullptr,
            &ciphertextLength,
            nullptr,
            &secretLength) <= 0) {
        throw std::runtime_error("Failed to determine ML-KEM output sizes.");
    }

    EncapsulationResult result;
    result.ciphertext.resize(ciphertextLength);
    result.sharedSecret.resize(secretLength);

    if (EVP_PKEY_encapsulate(
            ctx.get(),
            result.ciphertext.data(),
            &ciphertextLength,
            result.sharedSecret.data(),
            &secretLength) <= 0) {
        throw std::runtime_error("ML-KEM encapsulation failed.");
    }

    result.ciphertext.resize(ciphertextLength);
    result.sharedSecret.resize(secretLength);
    return result;
}

MLKEM1024::ByteVector MLKEM1024::decapsulate(const ByteVector& ciphertext) const {
    if (!key_) {
        throw std::runtime_error("ML-KEM key is not loaded.");
    }

    PkeyContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key_, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
        throw std::runtime_error("Failed to initialize ML-KEM decapsulation.");
    }

    std::size_t secretLength = 0;
    if (EVP_PKEY_decapsulate(
            ctx.get(),
            nullptr,
            &secretLength,
            ciphertext.data(),
            ciphertext.size()) <= 0) {
        throw std::runtime_error("Failed to determine ML-KEM shared-secret size.");
    }

    ByteVector sharedSecret(secretLength);
    if (EVP_PKEY_decapsulate(
            ctx.get(),
            sharedSecret.data(),
            &secretLength,
            ciphertext.data(),
            ciphertext.size()) <= 0) {
        throw std::runtime_error("ML-KEM decapsulation failed.");
    }

    sharedSecret.resize(secretLength);
    return sharedSecret;
}

bool MLKEM1024::hasKey() const noexcept {
    return key_ != nullptr;
}

}
