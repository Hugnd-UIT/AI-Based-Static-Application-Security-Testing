#include "../include/crypto.h"
#include <iostream>

void encryptData(const char* data) {
    // Hardcoded Cryptographic Key [CWE-321]
    const char* secret_key = "SuperSecretEncryptionKey123";
    std::cout << "Encrypting " << data << " with key " << secret_key << std::endl;
}
