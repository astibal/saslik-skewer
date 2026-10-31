#include "paired_tunnel.hpp"
#include "processes.hpp"
#include <QCoreApplication>
#include <array>
#include <future>
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
class Control final : public TunnelControl {
public:
    std::atomic_uint opens{}, renewals{}, closes{};
    bool reject{};
    bool late{};
    PairedTunnel open() override {
        ++opens;
        Tuntom::Endpoint endpoint;
        endpoint.id = 241;
        endpoint.leaseSeconds = 10;
        return {endpoint, QByteArray(16, char(9))};
    }
    void renew(const Tuntom::Endpoint&) override {
        ++renewals;
        // The packet worker must keep answering while control is blocked.
        Sleep(late ? 8000 : 500);
        if (reject) {
            throw std::runtime_error("Fixture renewal rejected");
        }
    }
    void close(const Tuntom::Endpoint&) override { ++closes; }
};
class Device final : public PacketDevice {
public:
    std::atomic_uint received{};
    HANDLE readEvent() const override { return nullptr; }
    std::optional<size_t> readPacket(std::span<uint8_t> buffer) override {
        if (++polls_ % 2 != 1) {
            return std::nullopt;
        }
        std::fill_n(buffer.begin(), 64, 0);
        buffer[0] = 0x45;
        buffer[3] = 64;
        return 64;
    }
    bool writePacket(std::span<const uint8_t> packet) override {
        require(packet.size() == 64 && packet[0] == 0x45, "Echo payload corrupted");
        ++received;
        return true;
    }

private:
    unsigned polls_{};
};
class Routes final : public TunnelRoutePolicy {
public:
    explicit Routes(std::atomic_bool& ready) : ready_(ready) {}
    unsigned activations{}, withdrawals{};
    bool bad_order{}, fail{};
    void activate(const Tuntom::Endpoint&) override {
        ++activations;
        bad_order |= ready_.load();
        if (fail) {
            throw std::runtime_error("Fixture route installation failed");
        }
    }
    void withdraw() noexcept override {
        ++withdrawals;
        bad_order |= ready_.load();
    }

private:
    std::atomic_bool& ready_;
};
class Packets final : public TunnelPacketWorker {
public:
    explicit Packets(std::atomic_bool& ready) : ready_(ready) {}
    unsigned preparations{}, polls{}, blocks{}, control_polls{};
    unsigned gate_calls{}, gate_denials{};
    HANDLE cancel_on_control{};
    bool bad_order{}, fail_prepare{}, fail_poll{};
    void prepare(const Tuntom::Endpoint& endpoint) override {
        thread_ = GetCurrentThreadId();
        ++preparations;
        bad_order |= ready_.load() || endpoint.id != 241;
        if (fail_prepare) {
            throw std::runtime_error("Fixture packet preparation failed");
        }
    }
    void pollControl() override {
        ++control_polls;
        bad_order |= blocks || GetCurrentThreadId() != thread_;
        if (cancel_on_control) SetEvent(cancel_on_control);
    }
    bool dataAllowed() override {
        ++gate_calls;
        bad_order |= blocks || GetCurrentThreadId() != thread_;
        // Exercise the service's payload gate while allowing handshake and
        // renewal to proceed. The pump must count these packets as discarded.
        if (gate_denials < 32) {
            ++gate_denials;
            return false;
        }
        return true;
    }
    void poll() override {
        ++polls;
        bad_order |= !ready_.load() || blocks || GetCurrentThreadId() != thread_;
        if (fail_poll) {
            throw std::runtime_error("Fixture packet processing failed");
        }
    }
    void block() noexcept override {
        ++blocks;
        bad_order |= ready_.load() || GetCurrentThreadId() != thread_;
    }
private:
    std::atomic_bool& ready_;
    DWORD thread_{};
};
void exercise(bool reject, bool late = false, bool route_failure = false, bool transport_loss = false,
              bool packet_failure = false) {
    Control control;
    control.reject = reject;
    control.late = late;
    Device device;
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(stop), "Cannot create cancellation event");
    std::atomic_bool ready{};
    Routes routes(ready);
    Packets packets(ready);
    packets.fail_poll = packet_failure;
    routes.fail = route_failure;
    // Cancelled startup must not consume an invitation or open a lease.
    SetEvent(stop.get());
    runPairedTunnel(device, control, "127.0.0.1", stop.get(), ready, &routes, &packets);
    require(control.opens == 0, "Cancelled startup opened control");
    require(routes.activations == 0 && routes.withdrawals == 0, "Cancelled startup touched routes");
    require(!packets.preparations && !packets.blocks, "Cancelled startup touched packets");
    ResetEvent(stop.get());
    UdpEndpoint server(UdpAddress::numeric("127.0.0.1", 40241));
    tuntom::ascon::key_type key{};
    key.fill(9);
    tuntom::SessionProtocol protocol(241, key, true, 1280, true, 300, true);
    auto run = std::async(std::launch::async, [&] {
        return runPairedTunnel(device, control, "127.0.0.1", stop.get(), ready,
                               packet_failure ? nullptr : &routes, &packets);
    });
    struct CancelOnExit {
        HANDLE stop;
        ~CancelOnExit() { SetEvent(stop); }
    } cancel{stop.get()};
    const auto started = TunnelPump::Clock::now();
    const auto deadline = started + std::chrono::seconds(late ? 14 : 8);
    bool saw_ready = false;
    bool saw_expired_pending = false;
    unsigned after_expiration = 0;
    unsigned during_renewal = 0;
    std::array<uint8_t, 65536> buffer{};
    while (run.wait_for(std::chrono::seconds(0)) != std::future_status::ready &&
           TunnelPump::Clock::now() < deadline) {
        saw_ready |= ready.load();
        if (control.renewals && !during_renewal) {
            during_renewal = device.received.load();
        }
        if (!reject && !late && !transport_loss && control.renewals && device.received > during_renewal + 8) {
            SetEvent(stop.get());
        }
        const auto now = TunnelPump::Clock::now();
        if (late && now > started + std::chrono::milliseconds(10300)) {
            require(!ready, "Pending renewal extended expired readiness");
            if (!saw_expired_pending) {
                after_expiration = device.received.load();
                saw_expired_pending = true;
            }
            require(device.received == after_expiration, "Data continued after lease expiration");
        }
        if (const auto datagram = server.receive(buffer)) {
            if (transport_loss && saw_ready) {
                // The control plane remains reachable but authenticated UDP
                // replies disappear. Routes must not survive this health loss.
                continue;
            }
            tuntom::Packet packet;
            std::vector<uint8_t> scratch;
            auto result = protocol.receive(buffer.data(), datagram->size, packet, scratch, now);
            if (!result.reply.empty()) {
                server.send(result.reply, datagram->source);
            }
            if (result.data) {
                if (packet.type == tuntom::PacketType::ping) {
                    packet.type = tuntom::PacketType::pong;
                }
                if (packet.type == tuntom::PacketType::pong || packet.type == tuntom::PacketType::data) {
                    server.send(protocol.encode(packet), datagram->source);
                }
            }
        }
        Sleep(1);
    }
    SetEvent(stop.get());
    bool failed = false;
    TunnelPump::Counters counters{};
    try {
        counters = run.get();
    } catch (const std::exception&) {
        failed = true;
    }
    require(failed == (reject || late || route_failure || transport_loss || packet_failure),
            "Unexpected renewal result");
    require(packets.preparations == 1 && packets.blocks && !packets.bad_order,
            "Packet worker lifetime or thread order incorrect");
    if (packet_failure) {
        require(packets.polls == 1 && control.closes == 1 && !ready,
                "Packet failure did not retire readiness and lease");
        return;
    }
    require(routes.activations == 1 && routes.withdrawals == 1 && !routes.bad_order,
            "Routes must activate before readiness and withdraw after readiness is cleared");
    require(control.closes == 1 && !ready, "Route teardown did not release lease and readiness");
    if (route_failure) {
        require(!saw_ready, "Failed route installation published readiness");
        return;
    }
    if (transport_loss) {
        require(saw_ready, "Transport-loss fixture never became ready");
        return;
    }
    require(!late || saw_expired_pending, "Expired pending renewal was not observed");
    require(saw_ready && !ready, "Readiness lifecycle incorrect");
    require(control.opens == 1 && control.renewals == 1 && control.closes == 1, "Control lifetime incorrect");
    require(device.received > during_renewal + 8, "Packet pump stalled during renewal");
    if (!failed) {
        require(packets.gate_denials == 32 && packets.gate_calls > packets.gate_denials &&
                    counters.not_ready >= packets.gate_denials,
                "Paired transport bypassed the worker-owned payload gate");
    }
}
} // namespace
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        {
            Control control;
            Device device;
            Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            require(bool(stop), "Cannot create pending-handshake cancellation event");
            std::atomic_bool ready{};
            Packets packets(ready);
            packets.cancel_on_control = stop.get();
            // No peer is listening: control must run before authenticated data.
            runPairedTunnel(device, control, "127.0.0.1", stop.get(), ready, nullptr, &packets);
            require(packets.control_polls == 1 && !packets.polls && !packets.bad_order &&
                        !ready && control.closes == 1,
                    "Pending handshake starved control or admitted packet processing");
        }
        exercise(false);
        exercise(true);
        exercise(false, true);
        exercise(false, false, true);
        exercise(false, false, false, true);
        exercise(false, false, false, false, true);
        {
            Control control;
            Device device;
            Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            std::atomic_bool ready{};
            Packets packets(ready);
            packets.fail_prepare = true;
            bool failed = false;
            try {
                runPairedTunnel(device, control, "127.0.0.1", stop.get(), ready, nullptr, &packets);
            } catch (const std::exception&) {
                failed = true;
            }
            require(failed && packets.preparations == 1 && packets.blocks == 1 &&
                        !packets.polls && !packets.bad_order && control.closes == 1,
                    "Partial packet preparation did not clean up");
        }
        std::cout << "PASS: paired owner, encrypted data, asynchronous renewal, rejection and cancellation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
