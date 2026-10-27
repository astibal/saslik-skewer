#pragma once
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <QTcpSocket>
#include <QByteArray>
#include <limits>
#include <stdexcept>

namespace PairingPlatform {
// Qt owns this socket and outlives TLS. No event loop is entered during the
// blocking exchange; OpenSSL is its sole reader until the socket is destroyed.
class Transport final {
public:
    explicit Transport(QTcpSocket& socket) {
        const auto native = static_cast<SOCKET>(socket.socketDescriptor());
        if (native == INVALID_SOCKET || native > static_cast<SOCKET>(std::numeric_limits<int>::max())) {
            throw std::runtime_error("Control socket cannot be represented by OpenSSL");
        }
        u_long nonblocking = 0;
        const DWORD timeout = 5000;
        if (ioctlsocket(native, FIONBIO, &nonblocking) ||
            setsockopt(native, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                       sizeof(timeout)) ||
            setsockopt(native, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout),
                       sizeof(timeout))) {
            throw std::runtime_error("Cannot configure control socket");
        }
        fd_ = static_cast<int>(native);
    }
    int descriptor() const { return fd_; }

private:
    int fd_{};
};
struct SignalGuard {};

inline QByteArray protect(const QByteArray& input, bool encrypt) {
    if (input.size() > 65536) {
        throw std::runtime_error("Pairing data exceeds bounds");
    }
    DATA_BLOB in{static_cast<DWORD>(input.size()),
                 reinterpret_cast<BYTE*>(const_cast<char*>(input.constData()))};
    DATA_BLOB out{};
    const bool ok = encrypt ? CryptProtectData(&in, L"Skewer pairing", nullptr, nullptr, nullptr,
                                               CRYPTPROTECT_UI_FORBIDDEN, &out)
                            : CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                                                 CRYPTPROTECT_UI_FORBIDDEN, &out);
    if (!ok) {
        throw std::runtime_error("Cannot protect or unlock pairing for this Windows user");
    }
    struct Release {
        DATA_BLOB& value;
        ~Release() {
            SecureZeroMemory(value.pbData, value.cbData);
            LocalFree(value.pbData);
        }
    } release{out};
    return QByteArray(reinterpret_cast<const char*>(out.pbData), out.cbData);
}
inline QByteArray encode(const QByteArray& input) {
    return QByteArray("SKDP1") + protect(input, true);
}
inline QByteArray decode(const QByteArray& input) {
    if (!input.startsWith("SKDP1")) {
        throw std::runtime_error("Pairing is not protected for this Windows user");
    }
    return protect(input.sliced(5), false);
}
} // namespace PairingPlatform
