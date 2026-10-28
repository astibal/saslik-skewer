#pragma once
#include "packet_tuple.hpp"
#include <chrono>
#include <compare>
#include <map>
#include <set>

namespace skewer::traffic {
struct ProcessIdentity {
    std::uint32_t pid{};
    std::uint64_t created{};
    auto operator<=>(const ProcessIdentity &) const = default;
};
struct FlowIdentity {
    ProcessIdentity process;
    std::uint64_t endpoint{};
    auto operator<=>(const FlowIdentity &) const = default;
};

// Diagnostic correlation, not authorization. One owner serializes access.
// Reverse-direction packets share an index entry. Multiple distinct process
// identities yield Ambiguous, even if their PIDs or executable names agree.
class FlowIndex final {
  public:
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;
    enum class Status { Unknown, Observed, Ambiguous, Unreliable };
    struct Match {
        Status status;
        std::optional<ProcessIdentity> process;
    };
    enum class Update { Applied, Ignored, Unreliable };

    explicit FlowIndex(std::size_t capacity = 4096, Clock::duration lifetime = std::chrono::minutes(5));
    // event_order is a monotonically comparable source timestamp, not wall time.
    // Closed records remain as tombstones until expiry to reject delayed opens.
    Update observe(FlowIdentity id, PacketTuple tuple, bool open, std::uint64_t event_order, Time now);
    Match lookup(PacketTuple tuple, Time now) const;
    // Stricter diagnostic lookup: multiple socket endpoints are ambiguous even
    // when they belong to the same process. Still not atomic OS ownership proof.
    std::optional<FlowIdentity> lookupFlow(PacketTuple tuple, Time now) const;
    void expire(Time now);
    // Signal observer loss/overflow explicitly. No match is returned until reset.
    void invalidate();
    // Only when starting a new observation epoch after stopping old producers.
    void reset();
    std::size_t size() const { return records_.size(); }

  private:
    struct TupleLess {
        bool operator()(const PacketTuple &a, const PacketTuple &b) const;
    };
    struct Record {
        PacketTuple tuple;
        std::uint64_t order;
        Time expires;
        bool open;
    };
    static PacketTuple canonical(PacketTuple tuple);
    void unindex(FlowIdentity id, const PacketTuple &tuple);
    const std::size_t capacity_;
    const Clock::duration lifetime_;
    bool reliable_{true};
    std::map<FlowIdentity, Record> records_;
    std::map<PacketTuple, std::set<FlowIdentity>, TupleLess> tuples_;
};
} // namespace skewer::traffic
