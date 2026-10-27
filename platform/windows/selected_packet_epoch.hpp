#pragma once
#include "selection_registry.hpp"
#include "../traffic/selected_packets.hpp"

namespace skewer::windows {
// One packet queue bound to one service-owned selection generation. Registry
// and queue share a worker thread; the registry must outlive this object.
// A trusted resolver is still required: diagnostic SOCKET/FLOW matches alone
// must never be promoted to unique packet ownership by this adapter.
template <typename CaptureContext> class SelectedPacketEpoch final {
    using Queue = skewer::traffic::SelectedPackets<CaptureContext>;

public:
    using Time = typename Queue::Time;
    using Ticket = typename Queue::Ticket;
    using Packet = typename Queue::Packet;
    struct TunnelState {
        Time now;
        bool healthy;
    };

    SelectedPacketEpoch(const SelectionRegistry& registry, SelectionRegistry::Entry selection,
                        std::size_t count, std::size_t bytes, std::chrono::steady_clock::duration lifetime)
        : registry_(registry), selection_(selection),
          queue_({selection.process.pid, selection.process.created}, count, bytes, lifetime) {
        if (!registry_.current(selection_)) {
            throw std::invalid_argument("Packet epoch requires a current selection");
        }
    }

    std::optional<Ticket> hold(std::span<const std::uint8_t> packet, CaptureContext context, Time now) {
        if (!registry_.current(selection_)) {
            queue_.stop();
            return std::nullopt;
        }
        return queue_.hold(packet, context, now);
    }

    // Call readiness again after ownership resolution, which may block. The
    // callback must refer to this transport epoch, not a replacement tunnel.
    // Any failed readiness check retires this queue; it cannot silently revive.
    template <typename Resolver, typename Readiness>
    std::optional<Packet> takeForTunnel(Ticket ticket, Resolver&& resolve, Readiness&& readiness) {
        try {
            const auto before = readiness();
            return queue_.takeForTunnel(ticket, before.now, registry_.current(selection_), before.healthy,
                                        std::forward<Resolver>(resolve), [&] {
                                            const auto after = readiness();
                                            return typename Queue::Readiness{
                                                after.now, registry_.current(selection_), after.healthy};
                                        });
        } catch (...) {
            queue_.stop();
            throw;
        }
    }

    void stop() { queue_.stop(); }
    std::size_t size() const { return queue_.size(); }

private:
    const SelectionRegistry& registry_;
    const SelectionRegistry::Entry selection_;
    Queue queue_;
};
} // namespace skewer::windows
