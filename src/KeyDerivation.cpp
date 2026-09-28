#include "KeyDerivation.hpp"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <climits>
#include <memory>
#include <stdexcept>

namespace nsg {
namespace {

using KdfPtr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using KdfContext = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

}

KeyDerivation::ByteVector KeyDerivation::randomBytes(std::uint32_t length) {
    ByteVector bytes(static_cast<std::size_t>(length));

    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const std::size_t remaining = bytes.size() - offset;
        const int chunk = remaining > static_cast<std::size_t>(INT_MAX)
            ? INT_MAX
            : static_cast<int>(remaining);

        if (RAND_bytes(bytes.data() + offset, chunk) != 1) {
            throw std::runtime_error("Failed to generate cryptographically secure random bytes.");
        }

        offset += static_cast<std::size_t>(chunk);
    }

    return bytes;
}

KeyDerivation::AES256Key KeyDerivation::deriveAES256Key(
    const ByteVector& classicalSecret,
    const ByteVector& postQuantumSecret,
    const ByteVector& salt,
    const std::string& context) {

    if (classicalSecret.empty() || postQuantumSecret.empty()) {
        throw std::runtime_error("Both classical and post-quantum secrets are required.");
    }

    ByteVector combined;
    combined.reserve(classicalSecret.size() + postQuantumSecret.size());
    combined.insert(combined.end(), classicalSecret.begin(), classicalSecret.end());
    combined.insert(combined.end(), postQuantumSecret.begin(), postQuantumSecret.end());

    KdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    if (!kdf) {
        throw std::runtime_error("Failed to load OpenSSL HKDF implementation.");
    }

    KdfContext ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create HKDF context.");
    }

    const char* digestName = "SHA512";
    const char* mode = "EXTRACT_AND_EXPAND";

    OSSL_PARAM params[6];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        const_cast<char*>(digestName),
        0);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_MODE,
        const_cast<char*>(mode),
        0);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        combined.data(),
        combined.size());
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT,
        const_cast<Byte*>(salt.data()),
        salt.size());
    params[4] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        const_cast<char*>(context.data()),
        context.size());
    params[5] = OSSL_PARAM_construct_end();

    AES256Key output{};
    if (EVP_KDF_derive(ctx.get(), output.data(), output.size(), params) != 1) {
        throw std::runtime_error("HKDF-SHA-512 key derivation failed.");
    }

    return output;
}

}
