#include "AES256.hpp"
#include "KeyDerivation.hpp"
#include "MLKEM1024.hpp"
#include "RSA4096.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using ByteVector = std::vector<std::uint8_t>;

ByteVector bytes(const std::string& text) {
    return ByteVector(text.begin(), text.end());
}

std::string text(const ByteVector& data) {
    return std::string(data.begin(), data.end());
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void testAES() {
    const auto key = nsg::AES256::generateKey();
    const ByteVector plaintext = bytes("Null-Sector Guard AES test");
    const ByteVector aad = bytes("test-aad");

    const auto encrypted = nsg::AES256::encrypt(plaintext, key, aad);
    const auto decrypted = nsg::AES256::decrypt(encrypted, key, aad);

    require(decrypted == plaintext, "AES decrypted data does not match plaintext.");
    std::cout << "[OK] AES-256-GCM" << std::endl;
}

void testRSA() {
    nsg::RSA4096 server;
    server.generateKeyPair();

    const std::string publicPem = server.publicKeyPEM();
    const std::string privatePem = server.privateKeyPEM();

    nsg::RSA4096 clientPublicKey;
    clientPublicKey.loadPublicKeyPEM(publicPem);

    nsg::RSA4096 serverPrivateKey;
    serverPrivateKey.loadPrivateKeyPEM(privatePem);

    const ByteVector secret = nsg::KeyDerivation::randomBytes(32);
    const ByteVector encrypted = clientPublicKey.encrypt(secret);
    const ByteVector decrypted = serverPrivateKey.decrypt(encrypted);

    require(decrypted == secret, "RSA decrypted data does not match plaintext.");
    std::cout << "[OK] RSA-4096 OAEP-SHA256" << std::endl;
}

void testMLKEM() {
    nsg::MLKEM1024 server;
    server.generateKeyPair();

    const std::string publicPem = server.publicKeyPEM();
    const std::string privatePem = server.privateKeyPEM();

    nsg::MLKEM1024 clientPublicKey;
    clientPublicKey.loadPublicKeyPEM(publicPem);

    nsg::MLKEM1024 serverPrivateKey;
    serverPrivateKey.loadPrivateKeyPEM(privatePem);

    const auto clientResult = clientPublicKey.encapsulate();
    const auto serverSecret = serverPrivateKey.decapsulate(clientResult.ciphertext);

    require(serverSecret == clientResult.sharedSecret, "ML-KEM shared secrets do not match.");
    std::cout << "[OK] ML-KEM-1024" << std::endl;
}

void testHybridFlow() {
    nsg::RSA4096 serverRSA;
    serverRSA.generateKeyPair();

    nsg::MLKEM1024 serverKEM;
    serverKEM.generateKeyPair();

    nsg::RSA4096 clientRSA;
    clientRSA.loadPublicKeyPEM(serverRSA.publicKeyPEM());

    nsg::MLKEM1024 clientKEM;
    clientKEM.loadPublicKeyPEM(serverKEM.publicKeyPEM());

    const ByteVector classicalSecret = nsg::KeyDerivation::randomBytes(32);
    const ByteVector rsaCiphertext = clientRSA.encrypt(classicalSecret);

    const auto kemResult = clientKEM.encapsulate();
    const ByteVector salt = nsg::KeyDerivation::randomBytes(32);

    const auto clientToServerKey = nsg::KeyDerivation::deriveAES256Key(
        classicalSecret,
        kemResult.sharedSecret,
        salt,
        "Null-Sector Guard C2S v1");

    const auto serverToClientKey = nsg::KeyDerivation::deriveAES256Key(
        classicalSecret,
        kemResult.sharedSecret,
        salt,
        "Null-Sector Guard S2C v1");

    require(clientToServerKey != serverToClientKey, "Directional AES keys must be different.");

    const ByteVector recoveredClassicalSecret = serverRSA.decrypt(rsaCiphertext);
    const ByteVector recoveredPostQuantumSecret = serverKEM.decapsulate(kemResult.ciphertext);

    const auto clientToServerKeyServer = nsg::KeyDerivation::deriveAES256Key(
        recoveredClassicalSecret,
        recoveredPostQuantumSecret,
        salt,
        "Null-Sector Guard C2S v1");

    const auto serverToClientKeyServer = nsg::KeyDerivation::deriveAES256Key(
        recoveredClassicalSecret,
        recoveredPostQuantumSecret,
        salt,
        "Null-Sector Guard S2C v1");

    require(clientToServerKey == clientToServerKeyServer, "C2S AES keys do not match.");
    require(serverToClientKey == serverToClientKeyServer, "S2C AES keys do not match.");

    const ByteVector message = bytes("Hybrid encrypted message");
    const ByteVector aad = bytes("session-1");

    const auto encrypted = nsg::AES256::encrypt(message, clientToServerKey, aad);
    const auto decrypted = nsg::AES256::decrypt(encrypted, clientToServerKeyServer, aad);

    require(text(decrypted) == "Hybrid encrypted message", "Hybrid AES message failed.");
    std::cout << "[OK] RSA + ML-KEM + HKDF + AES hybrid flow" << std::endl;
}

void testAESTamperDetection() {
    const auto key = nsg::AES256::generateKey();
    const ByteVector plaintext = bytes("tamper test");
    auto encrypted = nsg::AES256::encrypt(plaintext, key);

    if (!encrypted.ciphertext.empty()) {
        encrypted.ciphertext[0] ^= 0x01U;
    }

    bool failedAsExpected = false;
    try {
        static_cast<void>(nsg::AES256::decrypt(encrypted, key));
    } catch (const std::runtime_error&) {
        failedAsExpected = true;
    }

    require(failedAsExpected, "AES-GCM did not reject modified ciphertext.");
    std::cout << "[OK] AES-GCM tamper detection" << std::endl;
}

}

int main() {
    try {
        testAES();
        testRSA();
        testMLKEM();
        testHybridFlow();
        testAESTamperDetection();
        std::cout << "All Null-Sector Guard tests passed." << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] " << error.what() << std::endl;
        return 1;
    }
}
