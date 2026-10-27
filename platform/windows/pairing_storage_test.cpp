#include "pairing_windows.hpp"
#include <QCoreApplication>
#include <iostream>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        const QByteArray secret("public-test-credential-not-a-real-key");
        const auto encoded = PairingPlatform::encode(secret);
        if (encoded.contains(secret) || PairingPlatform::decode(encoded) != secret) {
            return 1;
        }
        for (auto invalid : {secret, encoded.left(8), encoded}) {
            if (invalid == encoded) {
                invalid[invalid.size() - 1] ^= 1;
            }
            bool rejected = false;
            try {
                (void)PairingPlatform::decode(invalid);
            } catch (const std::exception&) {
                rejected = true;
            }
            if (!rejected) {
                return 2;
            }
        }
        std::cout << "Pairing storage: roundtrip, plaintext and corruption checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 3;
    }
}
