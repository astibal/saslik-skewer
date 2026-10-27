#include "selected_packet_epoch.hpp"
#include <array>
#include <iostream>

using namespace skewer::windows;
using Epoch = SelectedPacketEpoch<unsigned>;
using Owner = skewer::traffic::PacketOwner;
using namespace std::chrono_literals;

namespace {
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
} // namespace

int main() {
    try {
        const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
        SelectionRegistry registry;
        auto selection = registry.retain(std::make_unique<ProcessTarget>(key));
        // Synthetic UDP/IPv4 payload. No packets are injected by this test.
        std::array<std::uint8_t, 28> packet{};
        packet[0] = 0x45;
        packet[3] = 28;
        packet[9] = 17;
        packet[12] = 10;
        packet[16] = 20;
        packet[21] = 1;
        packet[23] = 2;
        packet[25] = 8;
        const Epoch::Time now{};
        const auto ready = [&] { return Epoch::TunnelState{now, true}; };
        const auto owner = [&](auto, auto) {
            return Owner{Owner::State::Unique, skewer::traffic::ProcessIdentity{key.pid, key.created}};
        };
        Epoch healthy(registry, selection, 2, 4096, 1s);
        const auto ticket = healthy.hold(packet, 7, now);
        require(ticket.has_value(), "Cannot queue packet");
        auto delivered = healthy.takeForTunnel(*ticket, owner, ready);
        require(delivered && delivered->capture == 7 && delivered->bytes.size() == packet.size(),
                "Verified packet did not transfer to tunnel path");
        require(!healthy.takeForTunnel(*ticket, owner, ready), "Packet ticket replayed");

        for (unsigned scenario = 0; scenario < 5; ++scenario) {
            Epoch epoch(registry, selection, 2, 4096, 1s);
            const auto held = *epoch.hold(packet, 1, now);
            bool healthy_tunnel = scenario != 0;
            bool threw{};
            unsigned observations{};
            std::optional<Epoch::Packet> result;
            try {
                result = epoch.takeForTunnel(
                    held,
                    [&](auto tuple, auto time) {
                        if (scenario == 1) {
                            healthy_tunnel = false;
                        }
                        if (scenario == 2) {
                            require(registry.release(selection), "Cannot retire selection");
                            selection = registry.retain(std::make_unique<ProcessTarget>(key));
                        }
                        if (scenario == 3) {
                            throw std::runtime_error("Ownership unavailable");
                        }
                        return owner(tuple, time);
                    },
                    [&] {
                        if (scenario == 4 && ++observations == 2) {
                            throw std::runtime_error("Readiness unavailable");
                        }
                        return Epoch::TunnelState{now, healthy_tunnel};
                    });
            } catch (const std::runtime_error&) {
                threw = true;
            }
            require(!result, "Packet escaped after selection or tunnel failed");
            require(threw == (scenario >= 3), "Unexpected failure outcome");
            require(epoch.size() == 0 && !epoch.hold(packet, 0, now), "Retired packet epoch revived");
        }

        Epoch unresolved(registry, selection, 2, 4096, 1s);
        const auto unknown = *unresolved.hold(packet, 0, now);
        for (auto state : {Owner::State::Unknown, Owner::State::Ambiguous}) {
            require(!unresolved.takeForTunnel(
                        unknown, [=](auto, auto) { return Owner{state, {}}; }, ready),
                    "Unresolved ownership escaped");
        }
        require(registry.release(selection), "Cannot release final selection");
        require(!unresolved.hold(packet, 0, now) && unresolved.size() == 0,
                "Release retained queued traffic");
        std::cout << "PASS: selection-bound packet epochs, tunnel loss, stale work and ownership failures\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
