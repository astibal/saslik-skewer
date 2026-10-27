#include "tunnel_pump.hpp"
#include "wintun_device.hpp"
#include <deque>
#include <iostream>
#include <memory>

namespace {
using namespace skewer::windows;

uint16_t checksum(std::span<const uint8_t> bytes) {
    uint32_t sum = 0;
    for (size_t at = 0; at < bytes.size(); at += 2) {
        sum += static_cast<uint32_t>(bytes[at]) << 8;
        if (at + 1 < bytes.size()) {
            sum += bytes[at + 1];
        }
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

void setChecksum(std::vector<uint8_t>& packet, size_t offset, size_t start, size_t size) {
    packet[offset] = packet[offset + 1] = 0;
    const auto value = checksum(std::span(packet).subspan(start, size));
    packet[offset] = static_cast<uint8_t>(value >> 8);
    packet[offset + 1] = static_cast<uint8_t>(value);
}

// A deliberately narrow remote endpoint for the live test. It answers only
// unfragmented ICMP echo from 198.18.254.1 to 198.18.254.2, never forwards traffic.
class EchoPeer final : public PacketDevice {
public:
    HANDLE ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    unsigned replies{};
    EchoPeer() {
        if (!ready) {
            throw std::runtime_error("Cannot create echo event");
        }
    }
    ~EchoPeer() override { CloseHandle(ready); }
    HANDLE readEvent() const override { return ready; }
    std::optional<size_t> readPacket(std::span<uint8_t> buffer) override {
        if (pending_.empty()) {
            ResetEvent(ready);
            return std::nullopt;
        }
        auto packet = std::move(pending_.front());
        pending_.pop_front();
        if (packet.size() > buffer.size()) {
            throw std::runtime_error("Echo buffer too small");
        }
        std::copy(packet.begin(), packet.end(), buffer.begin());
        return packet.size();
    }
    bool writePacket(std::span<const uint8_t> packet) override {
        constexpr uint8_t addresses[]{198, 18, 254, 1, 198, 18, 254, 2};
        if (packet.size() < 28 || packet[0] != 0x45 || packet[9] != 1 || (packet[6] & 0x3f) != 0 ||
            packet[7] != 0 || packet[20] != 8 || packet[21] != 0 ||
            !std::equal(std::begin(addresses), std::end(addresses), packet.begin() + 12) ||
            checksum(packet.first(20)) != 0 || checksum(packet.subspan(20)) != 0) {
            return true; // Ignore unrelated OS discovery traffic.
        }
        if (pending_.size() >= 8) {
            return false;
        }
        std::vector<uint8_t> reply(packet.begin(), packet.end());
        for (size_t at = 0; at != 4; ++at) {
            std::swap(reply[12 + at], reply[16 + at]);
        }
        reply[20] = 0;
        setChecksum(reply, 22, 20, reply.size() - 20);
        setChecksum(reply, 10, 0, 20);
        pending_.push_back(std::move(reply));
        ++replies;
        SetEvent(ready);
        return true;
    }

private:
    std::deque<std::vector<uint8_t>> pending_;
};
} // namespace

int wmain(int argc, wchar_t** argv) {
    const bool remote = argc == 4 && std::wstring_view(argv[1]) == L"--remote";
    if (!remote && (argc != 3 || std::wstring_view(argv[1]) != L"--live")) {
        std::cerr << "Usage: tunnel_pump_live --live ABSOLUTE_WINTUN_DLL\n"
                     "   or: tunnel_pump_live --remote ABSOLUTE_WINTUN_DLL IPV4_PEER\n";
        return 2;
    }
    try {
        const auto name = L"SkewerLive-" + std::to_wstring(GetCurrentProcessId());
        WintunDevice device(loadWintun(argv[2]), name);
        EchoPeer echo;
        UdpEndpoint client_udp(UdpAddress::numeric(remote ? "0.0.0.0" : "127.0.0.1", 0));
        UdpEndpoint server_udp(UdpAddress::numeric("127.0.0.1", 0));
        tuntom::ascon::key_type key{};
        if (remote) {
            // Inherit the test PSK through the environment, never argv or logs.
            key = tuntom::parse_master_key();
        } else if (!tuntom::platform::random_bytes(key.data(), key.size())) {
            throw std::runtime_error("Test session entropy failed");
        }
        const std::wstring peer_text = remote ? argv[3] : L"";
        const auto peer =
            remote ? UdpAddress::numeric(std::string(peer_text.begin(), peer_text.end()).c_str(), 40242)
                   : server_udp.localAddress();
        TunnelPump client(device, client_udp, peer, remote ? 242 : 42, key);
        std::unique_ptr<TunnelPump> server;
        if (!remote) {
            server = std::make_unique<TunnelPump>(echo, server_udp, client_udp.localAddress(), 42, key, true);
        }
        tuntom::secure_zero(key.data(), key.size());
        std::wcout << L"ADAPTER " << name << std::endl;
        const auto deadline = TunnelPump::Clock::now() + std::chrono::seconds(45);
        // Leave time for the external HTTP and ICMP probes to finish. TCP can
        // produce three received packets before the application gets its body.
        const auto earliest_completion = TunnelPump::Clock::now() + std::chrono::seconds(remote ? 25 : 0);
        std::optional<TunnelPump::Time> completed;
        while (TunnelPump::Clock::now() < deadline) {
            const auto now = TunnelPump::Clock::now();
            client.step(now);
            if (server) {
                server->step(now);
            }
            if (client.counters().rx >= 3 && (remote || echo.replies >= 3)) {
                if (!completed) {
                    completed = now;
                }
                if (now >= earliest_completion && now - *completed >= std::chrono::seconds(1)) {
                    std::cout << "PASS live Wintun encrypted ICMP: tx=" << client.counters().tx
                              << " rx=" << client.counters().rx << " peer=" << (remote ? "Linux" : "loopback")
                              << std::endl;
                    return 0;
                }
            }
            Sleep(1);
        }
        throw std::runtime_error("Live Wintun echo timed out");
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
