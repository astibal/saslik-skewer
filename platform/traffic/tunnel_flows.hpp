#pragma once
#include "flow_index.hpp"
#include "packet_rewrite.hpp"

namespace skewer::traffic {
// A single worker owns one table for one tunnel-address epoch. Authorization
// happens before outbound(); identities must come from a live pinned process
// and socket, never from packet bytes or a PID-only diagnostic lookup.
class TunnelFlows final {
public:
    using Time = FlowIndex::Time;
    TunnelFlows(std::array<std::uint8_t, 4> address, std::size_t capacity = 4096,
                FlowIndex::Clock::duration idle = std::chrono::minutes(5), std::uint16_t first_port = 1024);
    bool outbound(FlowIdentity owner, std::span<std::uint8_t> packet, Time now);
    std::optional<FlowIdentity> inbound(std::span<std::uint8_t> packet, Time now);
    void release(FlowIdentity owner);
    void releaseProcess(ProcessIdentity process);
    void expire(Time now);
    void stop();
    std::size_t size() const { return flows_.size(); }

private:
    struct Key {
        FlowIdentity owner;
        PacketTuple tuple;
        bool operator<(const Key& other) const;
    };
    struct Mapping {
        PacketTuple original;
        PacketTuple translated;
        Time touched;
    };
    bool advance(Time now);
    const std::array<std::uint8_t, 4> address_;
    const std::size_t capacity_;
    const FlowIndex::Clock::duration idle_;
    // Never reuse a port in an epoch, even across protocols. Delayed UDP replies
    // must not be delivered to a replacement socket after expiry/PID reuse.
    // Exhaustion rejects new flows; only a fresh tunnel epoch gets a fresh table.
    unsigned next_port_;
    bool stopped_{};
    std::optional<Time> last_;
    std::map<Key, Mapping> flows_;
    std::map<std::uint16_t, Key> reverse_;
};
} // namespace skewer::traffic
