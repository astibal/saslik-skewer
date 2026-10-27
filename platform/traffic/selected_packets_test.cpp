#include "selected_packets.hpp"
#include <array>
#include <iostream>

using namespace skewer::traffic;
using Queue = SelectedPackets<unsigned>;
using State = PacketOwner::State;
using namespace std::chrono_literals;
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
int main() {
    try {
        const ProcessIdentity selected{42, 100};
        std::array<std::uint8_t, 28> packet{};
        packet[0] = 0x45;
        packet[3] = 28;
        packet[9] = 17;
        packet[12] = 10;
        packet[16] = 20;
        packet[21] = 1;
        packet[23] = 2;
        packet[25] = 8;
        const auto tuple = *parsePacketTuple(packet).tuple;
        const Queue::Time now{};
        const auto recheck = [&] { return Queue::Readiness{now, true, true}; };
        const auto owner = [&](auto candidate, auto time) {
            require(candidate == tuple && time == now, "Resolver saw wrong packet or time");
            return PacketOwner{State::Unique, selected};
        };
        Queue queue(selected, 2, 4096, 1s);
        const auto ticket = queue.hold(packet, 7, now);
        require(ticket.has_value(), "Hold failed");
        for (auto state : {State::Unknown, State::Ambiguous}) {
            require(
                !queue.takeForTunnel(
                    *ticket, now, true, true, [=](auto, auto) { return PacketOwner{state, {}}; }, recheck) &&
                    queue.size() == 1,
                "Unresolved packet escaped or vanished");
        }
        auto ready = queue.takeForTunnel(*ticket, now, true, true, owner, recheck);
        require(ready && ready->capture == 7 && ready->bytes.size() == packet.size(),
                "Selected transfer failed");
        require(!queue.takeForTunnel(*ticket, now, true, true, owner, recheck), "Ticket replayed");
        const auto other = *queue.hold(packet, 8, now);
        require(!queue.takeForTunnel(
                    other, now, true, true,
                    [](auto, auto) { return PacketOwner{State::Unique, ProcessIdentity{42, 101}}; },
                    recheck) &&
                    queue.size() == 0,
                "Recycled PID matched selection");
        const auto expired = *queue.hold(packet, 0, now);
        require(!queue.takeForTunnel(expired, now + 1s, true, true, owner, recheck),
                "Expired packet forwarded");
        for (unsigned failure = 0; failure < 4; ++failure) {
            Queue stopped(selected, 2, 4096, 1s);
            const auto first = *stopped.hold(packet, 0, now);
            stopped.hold(packet, 1, now);
            require(!stopped.takeForTunnel(
                        first, now, failure != 0, failure != 1,
                        [&](auto, auto) {
                            return PacketOwner{failure == 2 ? State::Unreliable : State::Unique, {}};
                        },
                        recheck),
                    "Failed epoch forwarded a packet");
            require(stopped.size() == 0 && !stopped.hold(packet, 0, now), "Failed epoch recovered silently");
        }
        Queue invalid(selected, 1, 4096, 1s);
        require(!invalid.hold({}, 0, now), "Empty packet accepted");
        auto fragment = packet;
        fragment[6] = 0x20;
        require(!invalid.hold(fragment, 0, now), "Fragment entered ownership queue");
        const auto exceptional = *invalid.hold(packet, 0, now);
        bool threw{};
        try {
            invalid.takeForTunnel(
                exceptional, now, true, true,
                [](auto, auto) -> PacketOwner { throw std::runtime_error("Resolver unavailable"); }, recheck);
        } catch (const std::runtime_error&) {
            threw = true;
        }
        require(threw && invalid.size() == 0 && !invalid.hold(packet, 0, now),
                "Resolver failure retained a usable epoch");
        for (unsigned failure = 0; failure < 5; ++failure) {
            Queue delayed(selected, 2, 4096, 1s);
            const auto held = *delayed.hold(packet, 0, now);
            bool threw = false;
            try {
                require(!delayed.takeForTunnel(held, now, true, true, owner,
                                               [&]() -> Queue::Readiness {
                                                   if (failure == 3) {
                                                       throw std::runtime_error("Readiness unavailable");
                                                   }
                                                   return {failure == 2   ? now + 1s
                                                           : failure == 4 ? now - 1ms
                                                                          : now,
                                                           failure != 0, failure != 1};
                                               }),
                        "Packet escaped after readiness changed during resolution");
            } catch (const std::exception&) {
                threw = true;
            }
            require(threw == (failure >= 3), "Unexpected readiness exception outcome");
            require(delayed.size() == 0, "Failed or expired packet remained queued");
            if (failure != 2) {
                require(!delayed.hold(packet, 0, now + 2s), "Failed epoch restarted");
            }
        }
        std::cout << "PASS: selected packet gating, fresh readiness, expiry and terminal failure\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
