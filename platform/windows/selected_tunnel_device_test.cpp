#include "packet_queue.hpp"
#include "selected_tunnel_device.hpp"
#include "tunnel_pump.hpp"
#include <iostream>

using namespace skewer::windows;
using namespace skewer::traffic;
namespace {
void check(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
std::vector<std::uint8_t> request() {
    std::vector<std::uint8_t> p(28);
    p[0] = 0x45;
    p[3] = 28;
    p[8] = 64;
    p[9] = 17;
    p[12] = 192;
    p[13] = 168;
    p[14] = 199;
    p[15] = 131;
    p[16] = 1;
    p[17] = 1;
    p[18] = 1;
    p[19] = 1;
    p[20] = 0xc3;
    p[21] = 0x50;
    p[23] = 53;
    p[25] = 8;
    return p;
}
std::vector<std::uint8_t> reply(std::vector<std::uint8_t> p) {
    for (unsigned i = 0; i < 4; ++i) {
        std::swap(p[12 + i], p[16 + i]);
    }
    std::swap(p[20], p[22]);
    std::swap(p[21], p[23]);
    return p;
}
} // namespace
int main() {
    try {
        const FlowIdentity owner{{42, 100}, 1};
        bool live = true, gate = true;
        SelectedTunnelDevice device(
            {10, 253, 0, 10}, [&](auto id) { return live && id == owner; }, [&] { return gate; }, 2);
        PacketQueue peerDevice;
        UdpEndpoint clientUdp(UdpAddress::numeric("127.0.0.1", 0));
        UdpEndpoint peerUdp(UdpAddress::numeric("127.0.0.1", 0));
        tuntom::ascon::key_type key{};
        key.fill(7);
        TunnelPump client(device, clientUdp, peerUdp.localAddress(), 42, key);
        TunnelPump peer(peerDevice, peerUdp, clientUdp.localAddress(), 42, key, true);
        const auto cycle = [&] {
            const auto now = TunnelPump::Clock::now();
            client.step(now);
            peer.step(now);
            Sleep(1);
        };
        for (unsigned i = 0;
             i < 300 && !(client.healthy(TunnelPump::Clock::now()) && peer.healthy(TunnelPump::Clock::now()));
             ++i) {
            cycle();
        }
        check(client.healthy(TunnelPump::Clock::now()) && peer.healthy(TunnelPump::Clock::now()),
              "Encrypted transport not ready");
        const auto original = request();
        check(device.enqueue(owner, original), "Capture enqueue failed");
        std::optional<std::vector<std::uint8_t>> translated;
        for (unsigned i = 0; i < 300 && !translated; ++i) {
            cycle();
            translated = peerDevice.takeReceived();
        }
        check(translated.has_value(), "Translated packet did not cross encrypted transport");
        check(parsePacketTuple(*translated).tuple->source[0] == 10, "Source not translated");
        check(peerDevice.enqueue(reply(*translated)), "Reply enqueue failed");
        std::optional<SelectedTunnelDevice::Packet> received;
        for (unsigned i = 0; i < 300 && !received; ++i) {
            cycle();
            received = device.takeReceived();
        }
        check(received && received->owner == owner &&
                  *parsePacketTuple(received->bytes).tuple == parsePacketTuple(original).tuple->reversed(),
              "Reply not restored to original socket");
        check(device.enqueue(owner, original), "Second enqueue failed");
        live = false;
        std::array<std::uint8_t, 1280> buffer{};
        check(!device.readPacket(buffer), "Dead owner's queued packet escaped");
        live = true;
        check(!device.writePacket(reply(*translated)), "Released reverse mapping survived");
        check(device.enqueue(owner, original), "Third enqueue failed");
        gate = false;
        check(!device.readPacket(buffer), "Unhealthy epoch sent data");
        gate = true;
        check(!device.enqueue(owner, original), "Retired device revived");
        check(WaitForSingleObject(device.readEvent(), 0) == WAIT_TIMEOUT, "Stopped queue event stayed set");
        SelectedTunnelDevice bounded({10, 253, 0, 10}, [&](auto) { return live; }, [] { return true; }, 1);
        check(bounded.enqueue(owner, original) && !bounded.enqueue(owner, original), "Queue limit missing");
        const auto size = bounded.readPacket(buffer);
        check(size.has_value(), "Bounded read failed");
        const auto translatedReply = reply(std::vector(buffer.begin(), buffer.begin() + *size));
        check(bounded.writePacket(translatedReply), "Bounded reply failed");
        live = false;
        check(!bounded.takeReceived(), "Queued reply survived owner exit");
        bool fail = true;
        SelectedTunnelDevice applications({10, 253, 0, 10}, [](auto) { return true; }, [] { return true; }, 8);
        const FlowIdentity other{{43, 101}, 2};
        check(applications.enqueue(owner, original), "First application enqueue failed");
        auto sent = applications.readPacket(buffer);
        check(sent.has_value(), "First application read failed");
        const auto firstReply = reply(std::vector(buffer.begin(), buffer.begin() + *sent));
        check(applications.enqueue(other, original), "Second application enqueue failed");
        sent = applications.readPacket(buffer);
        check(sent.has_value(), "Second application read failed");
        const auto secondReply = reply(std::vector(buffer.begin(), buffer.begin() + *sent));
        check(applications.writePacket(firstReply) && applications.writePacket(secondReply),
              "Cannot queue application replies");
        check(applications.enqueue(owner, original) && applications.enqueue(other, original),
              "Cannot queue application requests");
        applications.releaseProcess(owner.process);
        auto retained = applications.takeReceived();
        check(retained && retained->owner == other && !applications.takeReceived(),
              "Process Release retained a reply or removed the other application's reply");
        check(applications.readPacket(buffer).has_value() && !applications.readPacket(buffer),
              "Process Release did not remove only its queued requests");
        check(applications.enqueue(owner, original), "Reattached application enqueue failed");
        check(applications.readPacket(buffer).has_value(), "Reattached application read failed");
        check(!applications.writePacket(firstReply), "Late reply survived process Release and reattach");
        SelectedTunnelDevice broken({10, 253, 0, 10}, [&](auto) {
            if (fail) { throw std::runtime_error("Injected identity lookup failure"); }
            return true;
        }, [] { return true; });
        bool threw = false;
        try { broken.enqueue(owner, original); } catch (const std::runtime_error&) { threw = true; }
        check(threw, "Resolver failure hidden");
        fail = false;
        check(!broken.enqueue(owner, original), "Resolver failure did not retire epoch");
        std::cout << "PASS: translated encrypted round trip, owner exit and terminal gate\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
