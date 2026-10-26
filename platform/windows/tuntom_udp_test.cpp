#include "udp_endpoint.hpp"
#include <session.hpp>

#include <array>
#include <iostream>
#include <stdexcept>

namespace {
using skewer::windows::UdpAddress;
using skewer::windows::UdpEndpoint;
using tuntom::SessionProtocol;
using Wire = std::vector<std::uint8_t>;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct StopEvent {
    HANDLE handle{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    StopEvent() { require(handle != nullptr, "CreateEvent failed"); }
    ~StopEvent() { CloseHandle(handle); }
};

// Exercise the real protocol through Winsock, including its production entropy
// source. No mocked codec, network configuration, TUN device or administrator.
Wire transfer(UdpEndpoint& from, UdpEndpoint& to, const Wire& wire, HANDLE stop) {
    require(!wire.empty(), "Protocol produced no wire packet");
    require(from.send(wire, to.localAddress()), "Loopback UDP send blocked");
    std::array<uint8_t, 65536> buffer{};
    const auto deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        if (auto packet = to.receive(buffer)) {
            return {buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(packet->size)};
        }
        require(to.wait(stop, 100) != UdpEndpoint::Wait::Cancelled, "Unexpected cancellation");
    }
    throw std::runtime_error("Tuntom UDP receive timed out");
}

SessionProtocol::Received decode(SessionProtocol& session, const Wire& wire, tuntom::Packet& packet) {
    Wire scratch;
    return session.receive(wire.data(), wire.size(), packet, scratch, SessionProtocol::Clock::now());
}

void run(const char* ip) {
    StopEvent stop;
    UdpEndpoint client_socket(UdpAddress::numeric(ip, 0));
    UdpEndpoint server_socket(UdpAddress::numeric(ip, 0));
    tuntom::ascon::key_type key{};
    key.fill(0x37); // Public test fixture, never a deployed credential.
    SessionProtocol client(42, key, false, 1500, true, 300, true);
    SessionProtocol server(42, key, true, 1500, true, 300, true);
    tuntom::Packet packet;
    require(!client.ready() && !server.ready(), "Session ready before handshake");
    auto wire =
        transfer(client_socket, server_socket, client.begin(SessionProtocol::Clock::now()), stop.handle);
    auto response = decode(server, wire, packet).reply;
    wire = transfer(server_socket, client_socket, response, stop.handle);
    auto confirm = decode(client, wire, packet).reply;
    wire = transfer(client_socket, server_socket, confirm, stop.handle);
    auto ack = decode(server, wire, packet).reply;
    wire = transfer(server_socket, client_socket, ack, stop.handle);
    require(decode(client, wire, packet).activated, "Client did not confirm session");
    require(client.ready() && server.ready(), "Handshake did not establish session");

    tuntom::Packet outbound;
    outbound.type = tuntom::PacketType::data;
    outbound.tunnel_id = 42;
    outbound.payload.assign(1200, 0x45);
    outbound.original_length = static_cast<uint32_t>(outbound.payload.size());
    outbound.message_id = 1;
    auto encrypted = client.encode(outbound);
    require(std::search(encrypted.begin(), encrypted.end(), outbound.payload.begin(),
                        outbound.payload.end()) == encrypted.end(),
            "Plaintext present in encrypted datagram");

    auto corrupted = encrypted;
    corrupted.back() ^= 1;
    wire = transfer(client_socket, server_socket, corrupted, stop.handle);
    require(!decode(server, wire, packet).data, "Tampered ciphertext accepted");
    wire = transfer(client_socket, server_socket, encrypted, stop.handle);
    require(decode(server, wire, packet).data && packet.payload == outbound.payload,
            "Encrypted client data failed");
    wire = transfer(client_socket, server_socket, encrypted, stop.handle);
    require(decode(server, wire, packet).replay_drop, "Replay was not rejected");

    wire = transfer(server_socket, client_socket, server.encode(outbound), stop.handle);
    require(decode(client, wire, packet).data && packet.payload == outbound.payload,
            "Encrypted return data failed");
    auto other_key = key;
    other_key.front() ^= 1;
    SessionProtocol stranger(42, other_key, true, 1500, true, 300, true);
    SessionProtocol fresh_client(42, key, false, 1500, true, 300, true);
    wire = transfer(client_socket, server_socket, fresh_client.begin(SessionProtocol::Clock::now()),
                    stop.handle);
    auto rejected = decode(stranger, wire, packet);
    require(rejected.reply.empty() && !stranger.ready(), "Wrong PSK accepted");
    std::cout << "PASS Tuntom encrypted PFS session over UDP " << ip << '\n';
}
} // namespace

int main() {
    try {
        run("127.0.0.1");
        run("::1");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
