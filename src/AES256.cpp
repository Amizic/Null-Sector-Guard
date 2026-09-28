#include "AES256.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <climits>
#include <memory>
#include <stdexcept>

namespace nsg {
namespace {

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

int checkedIntSize(std::size_t value) {
    if (value > static_cast<std::size_t>(INT_MAX)) {
        throw std::runtime_error("Input is too large for a single OpenSSL AES operation.");
    }
    return static_cast<int>(value);
}

}

AES256::Key AES256::generateKey() {
    Key key{};
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw std::runtime_error("Failed to generate AES-256 key.");
    }
    return key;
}

AES256::EncryptedData AES256::encrypt(
    const ByteVector& plaintext,
    const Key& key,
    const ByteVector& aad) {

    EncryptedData result;

    if (RAND_bytes(result.nonce.data(), static_cast<int>(result.nonce.size())) != 1) {
        throw std::runtime_error("Failed to generate AES-GCM nonce.");
    }

    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create AES cipher context.");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to initialize AES-256-GCM.");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(result.nonce.size()),
            nullptr) != 1) {
        throw std::runtime_error("Failed to set AES-GCM nonce length.");
    }

    if (EVP_EncryptInit_ex(
            ctx.get(),
            nullptr,
            nullptr,
            key.data(),
            result.nonce.data()) != 1) {
        throw std::runtime_error("Failed to set AES-256-GCM key and nonce.");
    }

    int written = 0;

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(
                ctx.get(),
                nullptr,
                &written,
                aad.data(),
                checkedIntSize(aad.size())) != 1) {
            throw std::runtime_error("Failed to process AES-GCM AAD.");
        }
    }

    result.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    int totalWritten = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(
                ctx.get(),
                result.ciphertext.data(),
                &written,
                plaintext.data(),
                checkedIntSize(plaintext.size())) != 1) {
            throw std::runtime_error("AES-256-GCM encryption failed.");
        }
        totalWritten = written;
    }

    if (EVP_EncryptFinal_ex(
            ctx.get(),
            result.ciphertext.data() + totalWritten,
            &written) != 1) {
        throw std::runtime_error("AES-256-GCM finalization failed.");
    }
    totalWritten += written;
    result.ciphertext.resize(static_cast<std::size_t>(totalWritten));

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(result.tag.size()),
            result.tag.data()) != 1) {
        throw std::runtime_error("Failed to read AES-GCM authentication tag.");
    }

    return result;
}

AES256::ByteVector AES256::decrypt(
    const EncryptedData& encrypted,
    const Key& key,
    const ByteVector& aad) {

    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create AES cipher context.");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to initialize AES-256-GCM.");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(encrypted.nonce.size()),
            nullptr) != 1) {
        throw std::runtime_error("Failed to set AES-GCM nonce length.");
    }

    if (EVP_DecryptInit_ex(
            ctx.get(),
            nullptr,
            nullptr,
            key.data(),
            encrypted.nonce.data()) != 1) {
        throw std::runtime_error("Failed to set AES-256-GCM key and nonce.");
    }

    int written = 0;

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(
                ctx.get(),
                nullptr,
                &written,
                aad.data(),
                checkedIntSize(aad.size())) != 1) {
            throw std::runtime_error("Failed to process AES-GCM AAD.");
        }
    }

    ByteVector plaintext(encrypted.ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    int totalWritten = 0;
    if (!encrypted.ciphertext.empty()) {
        if (EVP_DecryptUpdate(
                ctx.get(),
                plaintext.data(),
                &written,
                encrypted.ciphertext.data(),
                checkedIntSize(encrypted.ciphertext.size())) != 1) {
            throw std::runtime_error("AES-256-GCM decryption failed.");
        }
        totalWritten = written;
    }

    Tag tagCopy = encrypted.tag;
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tagCopy.size()),
            tagCopy.data()) != 1) {
        throw std::runtime_error("Failed to set AES-GCM authentication tag.");
    }

    const int finalResult = EVP_DecryptFinal_ex(
        ctx.get(),
        plaintext.data() + totalWritten,
        &written);

    if (finalResult != 1) {
        throw std::runtime_error("AES-256-GCM authentication failed.");
    }

    totalWritten += written;
    plaintext.resize(static_cast<std::size_t>(totalWritten));
    return plaintext;
}

}
