#pragma once

// Winsock must precede windows.h (including indirect inclusion through Wintun).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace skewer::windows {

class UdpAddress final {
public:
    // Resolution belongs in a worker; this low-level interface accepts numeric IPs only.
    static UdpAddress numeric(const std::string& ip, uint16_t port);
    int family() const { return address_.ss_family; }
    uint16_t port() const;

private:
    friend class UdpEndpoint;
    sockaddr_storage address_{};
    int length_{};
};

class UdpEndpoint final {
public:
    enum class Wait { Network, PacketDevice, Cancelled, Timeout };
    struct Datagram {
        size_t size;
        UdpAddress source;
    };

    explicit UdpEndpoint(const UdpAddress& local);
    ~UdpEndpoint();
    UdpEndpoint(const UdpEndpoint&) = delete;
    UdpEndpoint& operator=(const UdpEndpoint&) = delete;

    UdpAddress localAddress() const;
    // nullopt means would-block; a zero-byte datagram is still a datagram.
    // Truncation throws instead of feeding partial ciphertext to the protocol.
    std::optional<Datagram> receive(std::span<uint8_t> buffer);
    bool send(std::span<const uint8_t> packet, const UdpAddress& destination);
    // Events are borrowed. Cancellation wins when multiple handles are ready.
    // Readiness is advisory: drain receive() until would-block after Network.
    Wait wait(HANDLE cancellation, DWORD timeout_ms, HANDLE packet_event = nullptr);

private:
    void close() noexcept;
    bool started_{};
    SOCKET socket_{INVALID_SOCKET};
    WSAEVENT event_{WSA_INVALID_EVENT};
};

} // namespace skewer::windows
