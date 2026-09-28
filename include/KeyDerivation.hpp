#pragma once

#include "Export.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace nsg {

class NSG_API KeyDerivation {
public:
    using Byte = std::uint8_t;
    using ByteVector = std::vector<Byte>;
    using AES256Key = std::array<Byte, 32>;

    // Generates cryptographically secure random bytes.
    // length is explicitly 32-bit to avoid platform-dependent protocol lengths.
    static ByteVector randomBytes(std::uint32_t length);

    // Derives one 256-bit AES key from a classical secret and an ML-KEM secret.
    // HKDF-SHA-512 is used internally.
    static AES256Key deriveAES256Key(
        const ByteVector& classicalSecret,
        const ByteVector& postQuantumSecret,
        const ByteVector& salt,
        const std::string& context = "Null-Sector Guard v1");
};

}
