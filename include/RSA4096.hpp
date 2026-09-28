#pragma once

#include "Export.hpp"

#include <cstdint>
#include <string>
#include <vector>

struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;

namespace nsg {

class NSG_API RSA4096 {
public:
    using Byte = std::uint8_t;
    using ByteVector = std::vector<Byte>;

    RSA4096();
    ~RSA4096();

    RSA4096(const RSA4096&) = delete;
    RSA4096& operator=(const RSA4096&) = delete;

    RSA4096(RSA4096&& other) noexcept;
    RSA4096& operator=(RSA4096&& other) noexcept;

    // Generates a new RSA-4096 public/private key pair.
    void generateKeyPair();

    // Returns the public key in PEM format.
    std::string publicKeyPEM() const;

    // Returns the private key in PEM format.
    // The returned PEM is not password protected.
    std::string privateKeyPEM() const;

    // Loads a public RSA key from PEM.
    void loadPublicKeyPEM(const std::string& pem);

    // Loads a private RSA key from PEM.
    void loadPrivateKeyPEM(const std::string& pem);

    // Encrypts a small byte sequence with RSA-OAEP using SHA-256.
    // With RSA-4096 and SHA-256, plaintext must not exceed 446 bytes.
    ByteVector encrypt(const ByteVector& plaintext) const;

    // Decrypts RSA-OAEP ciphertext with the private key.
    ByteVector decrypt(const ByteVector& ciphertext) const;

    // Returns true when a key is currently loaded.
    bool hasKey() const noexcept;

private:
    EVP_PKEY* key_;

    void replaceKey(EVP_PKEY* newKey);
};

}
