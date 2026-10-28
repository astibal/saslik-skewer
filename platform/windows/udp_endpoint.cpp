#include "udp_endpoint.hpp"

#include <limits>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace skewer::windows {
namespace {
[[noreturn]] void fail(const char* operation, int error = WSAGetLastError()) {
    throw std::system_error(error, std::system_category(), operation);
}

int bufferSize(size_t size) {
    if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::length_error("UDP buffer exceeds Winsock length range");
    }
    return static_cast<int>(size);
}
} // namespace

UdpAddress UdpAddress::numeric(const std::string& ip, uint16_t port) {
    if (ip.empty() || ip.find('\0') != std::string::npos) {
        throw std::invalid_argument("Invalid numeric UDP address");
    }
    UdpAddress result;
    auto* v4 = reinterpret_cast<sockaddr_in*>(&result.address_);
    if (InetPtonA(AF_INET, ip.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        result.length_ = sizeof(*v4);
        return result;
    }
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&result.address_);
    if (InetPtonA(AF_INET6, ip.c_str(), &v6->sin6_addr) != 1) {
        throw std::invalid_argument("Expected numeric IPv4 or IPv6 address");
    }
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(port);
    result.length_ = sizeof(*v6);
    return result;
}

uint16_t UdpAddress::port() const {
    if (family() == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&address_)->sin_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in6*>(&address_)->sin6_port);
}

bool UdpAddress::operator==(const UdpAddress& other) const {
    if (family() != other.family() || port() != other.port()) {
        return false;
    }
    if (family() == AF_INET) {
        const auto* left = reinterpret_cast<const sockaddr_in*>(&address_);
        const auto* right = reinterpret_cast<const sockaddr_in*>(&other.address_);
        return left->sin_addr.s_addr == right->sin_addr.s_addr;
    }
    if (family() == AF_INET6) {
        const auto* left = reinterpret_cast<const sockaddr_in6*>(&address_);
        const auto* right = reinterpret_cast<const sockaddr_in6*>(&other.address_);
        return left->sin6_scope_id == right->sin6_scope_id &&
               std::memcmp(&left->sin6_addr, &right->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return false;
}

UdpEndpoint::UdpEndpoint(const UdpAddress& local) {
    WSADATA data{};
    const int error = WSAStartup(MAKEWORD(2, 2), &data);
    if (error != 0) {
        fail("WSAStartup", error);
    }
    started_ = true;
    try {
        socket_ = WSASocketW(local.family(), SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        if (socket_ == INVALID_SOCKET) {
            fail("WSASocket");
        }
        // Never silently share a local port with another process.
        const BOOL exclusive = TRUE;
        if (setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                       sizeof(exclusive)) == SOCKET_ERROR) {
            fail("SO_EXCLUSIVEADDRUSE");
        }
        if (bind(socket_, reinterpret_cast<const sockaddr*>(&local.address_), local.length_) ==
            SOCKET_ERROR) {
            fail("UDP bind");
        }
        event_ = WSACreateEvent();
        if (event_ == WSA_INVALID_EVENT) {
            fail("WSACreateEvent");
        }
        // Event selection also makes the socket nonblocking. FD_WRITE wakes a
        // future sender after backpressure; no periodic polling is required.
        if (WSAEventSelect(socket_, event_, FD_READ | FD_WRITE) == SOCKET_ERROR) {
            fail("WSAEventSelect");
        }
    } catch (...) {
        close();
        throw;
    }
}

UdpEndpoint::~UdpEndpoint() {
    close();
}

void UdpEndpoint::close() noexcept {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    if (event_ != WSA_INVALID_EVENT) {
        WSACloseEvent(event_);
        event_ = WSA_INVALID_EVENT;
    }
    if (started_) {
        WSACleanup();
        started_ = false;
    }
}

UdpAddress UdpEndpoint::localAddress() const {
    UdpAddress result;
    result.length_ = sizeof(result.address_);
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&result.address_), &result.length_) ==
        SOCKET_ERROR) {
        fail("getsockname");
    }
    return result;
}

std::optional<UdpEndpoint::Datagram> UdpEndpoint::receive(std::span<uint8_t> buffer) {
    if (buffer.empty()) {
        throw std::invalid_argument("UDP receive buffer must not be empty");
    }
    Datagram result{};
    result.source.length_ = sizeof(result.source.address_);
    const int size = recvfrom(socket_, reinterpret_cast<char*>(buffer.data()), bufferSize(buffer.size()), 0,
                              reinterpret_cast<sockaddr*>(&result.source.address_), &result.source.length_);
    if (size == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            return std::nullopt;
        }
        fail("UDP receive", error);
    }
    result.size = static_cast<size_t>(size);
    return result;
}

bool UdpEndpoint::send(std::span<const uint8_t> packet, const UdpAddress& destination) {
    // A non-null pointer also supports legal empty datagrams.
    const char* data = packet.empty() ? "" : reinterpret_cast<const char*>(packet.data());
    const int size = sendto(socket_, data, bufferSize(packet.size()), 0,
                            reinterpret_cast<const sockaddr*>(&destination.address_), destination.length_);
    if (size == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            return false;
        }
        fail("UDP send", error);
    }
    if (static_cast<size_t>(size) != packet.size()) {
        throw std::runtime_error("Unexpected partial UDP send");
    }
    return true;
}

UdpEndpoint::Wait UdpEndpoint::wait(HANDLE cancellation, DWORD timeout_ms, HANDLE packet_event,
                                    HANDLE capture_event) {
    HANDLE handles[] = {cancellation, event_, nullptr, nullptr};
    DWORD count = 2;
    const DWORD packet_index = packet_event ? count++ : MAXDWORD;
    if (packet_event) {
        handles[packet_index] = packet_event;
    }
    const DWORD capture_index = capture_event ? count++ : MAXDWORD;
    if (capture_event) {
        handles[capture_index] = capture_event;
    }
    const DWORD result = WaitForMultipleObjects(count, handles, FALSE, timeout_ms);
    if (result == WAIT_OBJECT_0) {
        return Wait::Cancelled;
    }
    if (packet_event && result == WAIT_OBJECT_0 + packet_index) {
        return Wait::PacketDevice;
    }
    if (capture_event && result == WAIT_OBJECT_0 + capture_index) {
        return Wait::Capture;
    }
    if (result == WAIT_TIMEOUT) {
        return Wait::Timeout;
    }
    if (result != WAIT_OBJECT_0 + 1) {
        fail("UDP wait", static_cast<int>(GetLastError()));
    }
    WSANETWORKEVENTS events{};
    // Reset through Winsock, never ResetEvent: enumeration/reset must be atomic.
    if (WSAEnumNetworkEvents(socket_, event_, &events) == SOCKET_ERROR) {
        fail("WSAEnumNetworkEvents");
    }
    for (const auto bit : {FD_READ_BIT, FD_WRITE_BIT}) {
        if ((events.lNetworkEvents & (1L << bit)) && events.iErrorCode[bit]) {
            fail("UDP network event", events.iErrorCode[bit]);
        }
    }
    return Wait::Network;
}

} // namespace skewer::windows
