// tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <astrocrypt.hpp>
using namespace astrocrypt;
int main()
{

    {
        std::string message = "Hello World\n";
        std::cout << message << std::endl;
        std::cout << sha256_hash(message) << std::endl;
        printf("\n");
    }

    {
        using namespace CryptoPP;
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;
        InvertibleRSAFunction paramsServer;
        paramsServer.GenerateRandomWithKeySize(rng, 1024);

        RSA::PrivateKey privateKeyServer(paramsServer);
        RSA::PublicKey publicKeyServer(paramsServer);
        ////////////////////////////////////////////////

        std::string plain = "RSA Encryption", cipher, recovered;
        std::string s_rsa = serialize_rsa_key(publicKeyServer);
        std::cout << s_rsa << std::endl;
        std::cout << s_rsa.size() << std::endl;

        CryptoPP::RSA::PublicKey pubKey;
        if (!unserialize_rsa_key(s_rsa, &pubKey))
            return 0;

        cipher = rsa_encrypt(pubKey, plain);
        std::cout << cipher << std::endl;

        rsa_decrypt(privateKeyServer, cipher, &recovered);
        std::cout << recovered << std::endl;
    }

    //base64 encoding/decoding test
    {
        const char* buffer = "Hello";
        std::cout << std::string(buffer) << std::endl;
        std::string encoded = base64_encode(buffer);

        std::cout << encoded << std::endl;

        std::cout << base64_decode(encoded) << std::endl;
    }
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
