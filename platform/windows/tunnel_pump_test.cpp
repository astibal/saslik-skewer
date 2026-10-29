#include "tunnel_pump.hpp"
#include "packet_queue.hpp"
#include <array>
#include <deque>
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

class TestDevice final : public PacketDevice {
public:
    HANDLE event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::deque<std::vector<uint8_t>> outgoing, incoming;
    bool full{};
    TestDevice() { require(event != nullptr, "Event creation failed"); }
    ~TestDevice() override { CloseHandle(event); }
    HANDLE readEvent() const override { return event; }
    std::optional<size_t> readPacket(std::span<uint8_t> buffer) override {
        if (outgoing.empty()) {
            ResetEvent(event);
            return std::nullopt;
        }
        const auto packet = std::move(outgoing.front());
        outgoing.pop_front();
        require(packet.size() <= buffer.size(), "Test packet overflow");
        std::copy(packet.begin(), packet.end(), buffer.begin());
        return packet.size();
    }
    bool writePacket(std::span<const uint8_t> packet) override {
        if (full) {
            return false;
        }
        incoming.emplace_back(packet.begin(), packet.end());
        return true;
    }
};

std::vector<uint8_t> packet(bool ipv6, size_t size = 128) {
    std::vector<uint8_t> result(size, 0);
    result[0] = ipv6 ? 0x60 : 0x45;
    const auto length = ipv6 ? size - 40 : size;
    result[ipv6 ? 4 : 2] = static_cast<uint8_t>(length >> 8);
    result[ipv6 ? 5 : 3] = static_cast<uint8_t>(length);
    return result;
}

void testQuietPeer(const char* ip) {
    TestDevice device;
    UdpEndpoint client_udp(UdpAddress::numeric(ip, 0)), peer_udp(UdpAddress::numeric(ip, 0));
    tuntom::ascon::key_type key{};
    key.fill(9);
    TunnelPump client(device, client_udp, peer_udp.localAddress(), 42, key);
    tuntom::SessionProtocol peer(42, key, true, TunnelPump::inner_mtu, true, 300, true);
    auto now = TunnelPump::Clock::now();
    unsigned replies = 0;
    const auto cycle = [&] {
        client.step(now);
        std::array<uint8_t, 65536> buffer{};
        for (unsigned batch = 0; batch != 16; ++batch) {
            const auto datagram = peer_udp.receive(buffer);
            if (!datagram) {
                break;
            }
            tuntom::Packet input;
            std::vector<uint8_t> scratch;
            const auto result = peer.receive(buffer.data(), datagram->size, input, scratch, now);
            if (!result.reply.empty()) {
                require(peer_udp.send(result.reply, client_udp.localAddress()), "Handshake reply failed");
            }
            // Model a Linux peer that sends no unsolicited keepalives during
            // our five-second health window, but answers authenticated probes.
            if (result.data && input.type == tuntom::PacketType::ping && input.message_id != 0) {
                tuntom::Packet pong;
                pong.type = tuntom::PacketType::pong;
                pong.tunnel_id = 42;
                pong.message_id = input.message_id;
                require(peer_udp.send(peer.encode(pong), client_udp.localAddress()), "Probe reply failed");
                ++replies;
            }
        }
        Sleep(1);
    };
    for (unsigned attempt = 0; attempt != 200 && !client.healthy(now); ++attempt) {
        cycle();
    }
    require(client.healthy(now), "Quiet peer handshake failed");
    for (unsigned second = 0; second != 12; ++second) {
        now += std::chrono::seconds(1);
        for (unsigned attempt = 0; attempt != 10; ++attempt) {
            cycle();
        }
        require(client.healthy(now), "Responsive idle peer was declared unhealthy");
    }
    require(replies >= 12, "Periodic authenticated PING probes missing");
    now += TunnelPump::health_timeout;
    require(!client.healthy(now), "Silent peer remained healthy without replies");
    std::cout << "PASS: quiet peer liveness " << ip << '\n';
}

void test(const char* ip) {
    TestDevice client_device, server_device;
    UdpEndpoint client_udp(UdpAddress::numeric(ip, 0)), server_udp(UdpAddress::numeric(ip, 0));
    tuntom::ascon::key_type key{};
    key.fill(7);
    TunnelPump client(client_device, client_udp, server_udp.localAddress(), 42, key);
    TunnelPump server(server_device, server_udp, client_udp.localAddress(), 42, key, true);
    auto now = TunnelPump::Clock::now();
    client_device.outgoing.push_back(packet(false));
    client.step(now);
    require(client.counters().not_ready == 1, "Unconfirmed egress was not dropped");
    const auto cycle = [&] {
        client.step(now);
        server.step(now);
    };
    for (unsigned attempt = 0; attempt != 200 && !(client.healthy(now) && server.healthy(now)); ++attempt) {
        cycle();
        Sleep(1);
    }
    require(client.healthy(now) && server.healthy(now), "Pump handshake failed");
    require(server_device.incoming.empty(), "Pre-handshake data leaked");
    for (const bool ipv6 : {false, true}) {
        const auto data = packet(ipv6);
        client_device.outgoing.push_back(data);
        server_device.outgoing.push_back(data);
        for (unsigned attempt = 0;
             attempt != 100 && (client_device.incoming.empty() || server_device.incoming.empty());
             ++attempt) {
            cycle();
            Sleep(1);
        }
        require(!client_device.incoming.empty() && client_device.incoming.front() == data,
                "Return data failed");
        require(!server_device.incoming.empty() && server_device.incoming.front() == data,
                "Forward data failed");
        client_device.incoming.clear();
        server_device.incoming.clear();
    }
    UdpEndpoint stranger(UdpAddress::numeric(ip, 0));
    require(stranger.send(packet(false), client_udp.localAddress()), "Foreign send failed");
    for (unsigned attempt = 0; attempt != 100 && client.counters().foreign_peer == 0; ++attempt) {
        client.step(now);
        Sleep(1);
    }
    require(client.counters().foreign_peer == 1, "Foreign peer not rejected");
    client_device.outgoing.push_back(packet(false, 1400));
    client.step(now);
    require(client.counters().oversized == 1, "Oversized egress accepted");
    client_device.outgoing.push_back({0x45});
    client.step(now);
    require(client.counters().invalid == 1, "Truncated IP header accepted");
    server_device.full = true;
    client_device.outgoing.push_back(packet(false));
    for (unsigned attempt = 0; attempt != 100 && server.counters().backpressure == 0; ++attempt) {
        cycle();
        Sleep(1);
    }
    require(server.counters().backpressure == 1, "Full device ring ignored");
    // Stop servicing the server. No cached confirmed state may keep data open.
    now += TunnelPump::health_timeout + std::chrono::seconds(1);
    require(!client.healthy(now), "Stale tunnel remained healthy");
    const auto dropped = client.counters().not_ready;
    client_device.outgoing.push_back(packet(false));
    client.step(now);
    require(client.counters().not_ready == dropped + 1, "Traffic escaped after health timeout");
    server_device.full = false;
    // Advance the monotonic clock through idle restart/rekey without sleeping.
    now += std::chrono::minutes(3);
    for (unsigned attempt = 0; attempt != 200; ++attempt) {
        cycle();
        if (client.healthy(now) && server.healthy(now)) {
            break;
        }
        Sleep(1);
    }
    require(client.healthy(now) && server.healthy(now), "Session did not recover after idle restart");
    server_device.incoming.clear();
    client_device.outgoing.push_back(packet(true));
    for (unsigned attempt = 0; attempt != 100 && server_device.incoming.empty(); ++attempt) {
        cycle();
        Sleep(1);
    }
    require(!server_device.incoming.empty(), "New session did not carry data");
    HANDLE stop = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    require(stop != nullptr, "Stop event failed");
    client.run(stop);
    CloseHandle(stop);
    require(!client.healthy(now), "Stopped worker retained healthy status");
    std::cout << "PASS: packet pump " << ip << '\n';
}
} // namespace

void testDataGate() {
    TestDevice left, right;
    UdpEndpoint a(UdpAddress::numeric("127.0.0.1", 0)), b(UdpAddress::numeric("127.0.0.1", 0));
    tuntom::ascon::key_type key{};
    key.fill(8);
    bool allowed = true;
    TunnelPump client(left, a, b.localAddress(), 43, key, false, [&] { return allowed; });
    TunnelPump server(right, b, a.localAddress(), 43, key, true);
    auto cycle = [&] {
        const auto now = TunnelPump::Clock::now();
        client.step(now);
        server.step(now);
        Sleep(1);
    };
    for (unsigned i = 0; i < 300 && !client.healthy(TunnelPump::Clock::now()); ++i) {
        cycle();
    }
    require(client.healthy(TunnelPump::Clock::now()), "Gate fixture handshake failed");
    allowed = false;
    left.outgoing.push_back(packet(false));
    right.outgoing.push_back(packet(false));
    for (unsigned i = 0; i < 40; ++i) {
        cycle();
    }
    require(left.incoming.empty() && right.incoming.empty(), "Denied gate passed data");
    require(client.counters().not_ready >= 2, "Both data directions must be denied");
    // Protected pause must suppress payload, not authenticated keepalives.
    // Hold it longer than the liveness timeout so this cannot pass merely on
    // the handshake's recent timestamp. Resuming must reuse the live transport.
    const auto paused_until = TunnelPump::Clock::now() + TunnelPump::health_timeout +
                              std::chrono::seconds(1);
    while (TunnelPump::Clock::now() < paused_until) {
        cycle();
    }
    const auto resumed_at = TunnelPump::Clock::now();
    require(client.healthy(resumed_at) && server.healthy(resumed_at),
            "Protected data pause interrupted authenticated transport liveness");
    require(left.incoming.empty() && right.incoming.empty(), "Paused transport delivered payload");
    allowed = true;
    for (unsigned i = 0; i < 10; ++i) {
        cycle();
    }
    require(left.incoming.empty() && right.incoming.empty(), "Denied data survived gate reopening");
    left.outgoing.push_back(packet(false));
    right.outgoing.push_back(packet(false));
    for (unsigned i = 0; i < 40; ++i) {
        cycle();
    }
    require(left.incoming.size() == 1 && right.incoming.size() == 1, "Fresh authorized data missing");
    std::cout << "PASS: packet-boundary authorization in both directions\n";
}

int main() {
    try {
        {
            PacketQueue queue(1, 4);
            std::array<std::uint8_t, 4> data{1, 2, 3, 4}, buffer{};
            require(!queue.enqueue({}) && !queue.writePacket({}), "Empty queue packet accepted");
            require(queue.enqueue(data) && !queue.enqueue(data), "Queue capacity not enforced");
            require(WaitForSingleObject(queue.readEvent(), 0) == WAIT_OBJECT_0, "Queue did not wake pump");
            data[0] = 9;
            require(queue.readPacket(buffer) == 4 && buffer[0] == 1, "Queue did not own packet bytes");
            require(WaitForSingleObject(queue.readEvent(), 0) == WAIT_TIMEOUT, "Queue event remained set");
            require(queue.writePacket(data) && !queue.writePacket(data), "Inbound bound missing");
            require(queue.takeReceived().has_value() && !queue.takeReceived(), "Inbound dequeue failed");
            std::array<std::uint8_t, 5> big{};
            require(!queue.enqueue(big) && !queue.writePacket(big), "MTU bound missing");
            require(queue.enqueue(data) && queue.writePacket(data), "Queue reuse failed");
            queue.stop();
            require(!queue.enqueue(data) && !queue.writePacket(data) && !queue.takeReceived() &&
                        !queue.readPacket(buffer),
                    "Stopped queue retained packets");
            std::cout << "PASS: bounded packet bridge ownership, events and terminal stop\n";
        }
        testDataGate();
        test("127.0.0.1");
        test("::1");
        testQuietPeer("127.0.0.1");
        testQuietPeer("::1");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
