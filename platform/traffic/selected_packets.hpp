#pragma once
#include "flow_index.hpp"
#include "pending_packets.hpp"
#include <functional>

namespace skewer::traffic {
// This contract is deliberately distinct from diagnostic FlowIndex::Match.
// Only a trusted ownership resolver may supply Unique. Observing one process
// does not prove uniqueness against unobserved processes sharing the tuple.
struct PacketOwner {
    enum class State { Unknown, Ambiguous, Unique, Unreliable };
    State state{State::Unknown};
    std::optional<ProcessIdentity> process;
};

// Bounded outbound queue for one verified process and one observation/tunnel
// epoch. Single worker, no locks, no direct-network reinjection path. The
// external owner retains the process handle and checks liveness each time.
template <typename CaptureContext> class SelectedPackets final {
    struct Context {
        CaptureContext capture;
        PacketTuple tuple;
    };
    using Queue = PendingPackets<Context>;

public:
    using Time = typename Queue::Time;
    using Ticket = typename Queue::Ticket;
    struct Packet {
        std::vector<std::uint8_t> bytes;
        CaptureContext capture;
    };
    SelectedPackets(ProcessIdentity selected, std::size_t count, std::size_t bytes,
                    typename Queue::Clock::duration lifetime)
        : selected_(selected), queue_(count, bytes, lifetime) {
        if (!selected.pid || !selected.created) {
            throw std::invalid_argument("Invalid selected identity");
        }
    }
    std::optional<Ticket> hold(std::span<const std::uint8_t> packet, CaptureContext capture, Time now) {
        queue_.expire(now);
        const auto parsed = parsePacketTuple(packet);
        if (parsed.status != TupleStatus::Parsed || !parsed.tuple) {
            return std::nullopt;
        }
        return queue_.hold(packet, {capture, *parsed.tuple}, now);
    }
    // Resolver is called with this ticket's parsed tuple, never one supplied
    // alongside the ticket by a caller. It must resolve at decision time.
    template <typename Resolver>
    std::optional<Packet> takeForTunnel(Ticket ticket, Time now, bool process_alive, bool tunnel_healthy,
                                        Resolver&& resolve) {
        queue_.expire(now);
        if (!process_alive || !tunnel_healthy) {
            stop();
            return std::nullopt;
        }
        const auto context = queue_.context(ticket, now);
        if (!context) {
            return std::nullopt;
        }
        PacketOwner owner;
        try {
            owner = std::invoke(std::forward<Resolver>(resolve), context->tuple, now);
        } catch (...) {
            stop();
            throw;
        }
        if (owner.state == PacketOwner::State::Unreliable ||
            (owner.state == PacketOwner::State::Unique && !owner.process)) {
            stop();
            return std::nullopt;
        }
        if (owner.state != PacketOwner::State::Unique) {
            return std::nullopt;
        }
        if (*owner.process != selected_) {
            queue_.discard(ticket);
            return std::nullopt;
        }
        auto packet = queue_.take(ticket, now);
        if (!packet) {
            return std::nullopt;
        }
        return Packet{std::move(packet->bytes), packet->context.capture};
    }
    void stop() { queue_.stop(); }
    std::size_t expire(Time now) { return queue_.expire(now); }
    std::size_t size() const { return queue_.size(); }

private:
    const ProcessIdentity selected_;
    Queue queue_;
};
} // namespace skewer::traffic
