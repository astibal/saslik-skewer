#include "udp_endpoint.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <vector>

using namespace skewer::windows;

namespace {
void check(bool condition, const char *message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct Event {
    HANDLE handle{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Event() { check(handle != nullptr, "CreateEvent"); }
    ~Event() { CloseHandle(handle); }
    Event(const Event &) = delete;
    Event &operator=(const Event &) = delete;
};

UdpEndpoint::Datagram receive(UdpEndpoint &endpoint, HANDLE stop, std::span<uint8_t> buffer) {
    const ULONGLONG deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        if (auto packet = endpoint.receive(buffer)) {
            return *packet;
        }
        check(endpoint.wait(stop, 100) != UdpEndpoint::Wait::Cancelled, "Unexpected cancellation");
    }
    throw std::runtime_error("Loopback datagram timed out");
}

void loopback(const char *ip) {
    Event stop;
    Event packet;
    Event capture;
    UdpEndpoint sender(UdpAddress::numeric(ip, 0));
    UdpEndpoint receiver(UdpAddress::numeric(ip, 0));
    const auto destination = receiver.localAddress();
    check(destination.port() != 0, "Ephemeral port missing");
    bool rejected = false;
    try {
        UdpEndpoint duplicate(destination);
    } catch (const std::system_error &) {
        rejected = true;
    }
    check(rejected, "Exclusive bind accepted duplicate");

    std::array<uint8_t, 4096> buffer{};
    check(!receiver.receive(buffer), "Empty receive must would-block");
    // Consume any initial writable notification before testing idle waits.
    for (int attempt = 0; attempt != 4; ++attempt) {
        if (receiver.wait(stop.handle, 10) == UdpEndpoint::Wait::Timeout) {
            break;
        }
    }
    check(receiver.wait(stop.handle, 10) == UdpEndpoint::Wait::Timeout, "Idle event spins");
    SetEvent(packet.handle);
    check(receiver.wait(stop.handle, 100, packet.handle) == UdpEndpoint::Wait::PacketDevice,
          "Packet device notification missing");
    ResetEvent(packet.handle);
    SetEvent(capture.handle);
    check(receiver.wait(stop.handle, 100, nullptr, capture.handle) == UdpEndpoint::Wait::Capture,
          "Capture notification without a packet device missing");
    check(receiver.wait(stop.handle, 100, packet.handle, capture.handle) == UdpEndpoint::Wait::Capture,
          "Capture notification alongside a packet device missing");
    SetEvent(packet.handle);
    check(receiver.wait(stop.handle, 100, packet.handle, capture.handle) == UdpEndpoint::Wait::PacketDevice,
          "Queued device output must not starve behind host capture");
    ResetEvent(packet.handle);
    ResetEvent(capture.handle);
    check(receiver.wait(stop.handle, 10, packet.handle, capture.handle) == UdpEndpoint::Wait::Timeout,
          "Drained device/capture events spin");

    std::vector<uint8_t> payload(1400, 0xa5);
    for (int index = 0; index != 16; ++index) {
        payload.front() = static_cast<uint8_t>(index);
        check(sender.send(payload, destination), "Loopback send blocked");
        check(receiver.wait(stop.handle, 2000) == UdpEndpoint::Wait::Network,
              "Incoming datagram did not wake network wait");
        auto received = receive(receiver, stop.handle, buffer);
        check(received.size == payload.size(), "Datagram length changed");
        check(std::equal(payload.begin(), payload.end(), buffer.begin()), "Datagram contents changed");
        check(received.source.port() == sender.localAddress().port(), "Source port missing");
        check(receiver.send(std::span(buffer).first(received.size), received.source), "Reply blocked");
        check(receive(sender, stop.handle, buffer).size == payload.size(), "Reply missing");
    }

    check(sender.send({}, destination), "Empty datagram send failed");
    check(receive(receiver, stop.handle, buffer).size == 0, "Empty datagram lost");
    check(sender.send(payload, destination), "Truncation test send failed");
    rejected = false;
    try {
        receive(receiver, stop.handle, std::span(buffer).first(1));
    } catch (const std::system_error &error) {
        rejected = error.code().value() == WSAEMSGSIZE;
    }
    check(rejected, "Truncated datagram accepted");
    check(!receiver.receive(buffer), "Truncated datagram remained queued");

    rejected = false;
    try {
        receiver.wait(nullptr, 0);
    } catch (const std::system_error &) {
        rejected = true;
    }
    check(rejected, "Invalid cancellation handle accepted");

    rejected = false;
    try {
        const std::vector<uint8_t> oversized(65536);
        sender.send(oversized, destination);
    } catch (const std::system_error &error) {
        rejected = error.code().value() == WSAEMSGSIZE;
    }
    check(rejected, "Oversized datagram accepted");

    check(sender.send(payload, destination), "Cancellation test send failed");
    SetEvent(stop.handle);
    SetEvent(packet.handle);
    SetEvent(capture.handle);
    check(receiver.wait(stop.handle, 100, packet.handle, capture.handle) == UdpEndpoint::Wait::Cancelled,
          "Cancellation must take precedence");
    std::cout << "PASS UDP " << ip << '\n';
}
} // namespace

int main() {
    try {
        bool rejected = false;
        try {
            UdpAddress::numeric("not-an-ip", 1);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        check(rejected, "Hostname accepted by numeric parser");
        loopback("127.0.0.1");
        loopback("::1");
        // Warm Winsock first; then repeated construction must not leak handles.
        DWORD before{}, after{};
        check(GetProcessHandleCount(GetCurrentProcess(), &before), "Handle count failed");
        for (int index = 0; index != 100; ++index) {
            UdpEndpoint endpoint(UdpAddress::numeric("127.0.0.1", 0));
        }
        check(GetProcessHandleCount(GetCurrentProcess(), &after), "Handle count failed");
        check(after <= before, "UDP lifecycle leaked handles");
        std::cout << "PASS UDP lifecycle\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
