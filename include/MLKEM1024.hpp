#pragma once

#include "Export.hpp"

#include <cstdint>
#include <string>
#include <vector>

struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;

namespace nsg {

class NSG_API MLKEM1024 {
public:
    using Byte = std::uint8_t;
    using ByteVector = std::vector<Byte>;

    struct EncapsulationResult {
        ByteVector ciphertext;
        ByteVector sharedSecret;
    };

    MLKEM1024();
    ~MLKEM1024();

    MLKEM1024(const MLKEM1024&) = delete;
    MLKEM1024& operator=(const MLKEM1024&) = delete;

    MLKEM1024(MLKEM1024&& other) noexcept;
    MLKEM1024& operator=(MLKEM1024&& other) noexcept;

    // Generates a new ML-KEM-1024 public/private key pair.
    void generateKeyPair();

    // Returns the public key in PEM format.
    std::string publicKeyPEM() const;

    // Returns the private key in PEM format.
    // The returned PEM is not password protected.
    std::string privateKeyPEM() const;

    // Loads an ML-KEM public key from PEM.
    void loadPublicKeyPEM(const std::string& pem);

    // Loads an ML-KEM private key from PEM.
    void loadPrivateKeyPEM(const std::string& pem);

    // Encapsulates a new shared secret using the loaded public key.
    // Send ciphertext to the private-key owner and keep sharedSecret locally.
    EncapsulationResult encapsulate() const;

    // Recovers the shared secret from the received ciphertext.
    ByteVector decapsulate(const ByteVector& ciphertext) const;

    // Returns true when a key is currently loaded.
    bool hasKey() const noexcept;

private:
    EVP_PKEY* key_;

    void replaceKey(EVP_PKEY* newKey);
};

}
