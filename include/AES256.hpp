#pragma once

#include "Export.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace nsg {

class NSG_API AES256 {
public:
    using Byte = std::uint8_t;
    using ByteVector = std::vector<Byte>;
    using Key = std::array<Byte, 32>;
    using Nonce = std::array<Byte, 12>;
    using Tag = std::array<Byte, 16>;

    struct EncryptedData {
        ByteVector ciphertext;
        Nonce nonce{};
        Tag tag{};
    };

    // Generates a random 256-bit AES key.
    static Key generateKey();

    // Encrypts plaintext with AES-256-GCM.
    // A fresh 96-bit nonce is generated automatically.
    // AAD is authenticated but is not encrypted.
    static EncryptedData encrypt(
        const ByteVector& plaintext,
        const Key& key,
        const ByteVector& aad = {});

    // Decrypts and authenticates AES-256-GCM data.
    // Throws std::runtime_error if authentication fails.
    static ByteVector decrypt(
        const EncryptedData& encrypted,
        const Key& key,
        const ByteVector& aad = {});
};

}
