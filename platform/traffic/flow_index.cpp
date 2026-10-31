#include "flow_index.hpp"
#include <stdexcept>
#include <tuple>

namespace skewer::traffic {
bool FlowIndex::TupleLess::operator()(const PacketTuple &a, const PacketTuple &b) const {
    return std::tie(a.ipv6, a.protocol, a.source, a.destination, a.source_port, a.destination_port) <
           std::tie(b.ipv6, b.protocol, b.source, b.destination, b.source_port, b.destination_port);
}
PacketTuple FlowIndex::canonical(PacketTuple tuple) {
    const auto reverse = tuple.reversed();
    return TupleLess{}(reverse, tuple) ? reverse : tuple;
}
FlowIndex::FlowIndex(std::size_t capacity, Clock::duration lifetime)
    : capacity_(capacity), lifetime_(lifetime) {
    if (!capacity || lifetime <= Clock::duration::zero()) {
        throw std::invalid_argument("Flow index requires positive capacity and lifetime");
    }
}
void FlowIndex::unindex(FlowIdentity id, const PacketTuple &tuple) {
    const auto found = tuples_.find(tuple);
    if (found == tuples_.end()) {
        return;
    }
    found->second.erase(id);
    if (found->second.empty()) {
        tuples_.erase(found);
    }
}
FlowIndex::Update FlowIndex::observe(FlowIdentity id, PacketTuple tuple, bool open, std::uint64_t order,
                                     Time now) {
    if (!reliable_) {
        return Update::Unreliable;
    }
    if (!id.process.pid || !id.process.created || !id.endpoint || !order ||
        (tuple.protocol != 6 && tuple.protocol != 17)) {
        invalidate();
        return Update::Unreliable;
    }
    tuple = canonical(tuple);
    auto found = records_.find(id);
    if (found != records_.end()) {
        auto &record = found->second;
        if (record.tuple != tuple) {
            // One endpoint identity cannot silently change its endpoints.
            invalidate();
            return Update::Unreliable;
        }
        if (order < record.order || (order == record.order && (open || !record.open))) {
            return Update::Ignored;
        }
        if (!record.open && open) {
            return Update::Ignored; // A closed endpoint never resurrects in this epoch.
        }
        if (!open) {
            unindex(id, tuple);
        }
        record.order = order;
        record.open = open;
        // Duplicate opens must not extend an entry indefinitely.
        return Update::Applied;
    }
    if (records_.size() >= capacity_) {
        // Evicting a colliding owner could turn Ambiguous into a false match.
        invalidate();
        return Update::Unreliable;
    }
    try {
        const auto expires = now > Time::max() - lifetime_ ? Time::max() : now + lifetime_;
        records_.emplace(id, Record{tuple, order, expires, open});
        if (open) {
            tuples_[tuple].insert(id);
        }
    } catch (...) {
        invalidate(); // Never leave a partially updated secondary index usable.
        throw;
    }
    return Update::Applied;
}
FlowIndex::Match FlowIndex::lookup(PacketTuple tuple, Time now) const {
    if (!reliable_) {
        return {Status::Unreliable, std::nullopt};
    }
    const auto found = tuples_.find(canonical(tuple));
    if (found == tuples_.end()) {
        return {Status::Unknown, std::nullopt};
    }
    std::optional<ProcessIdentity> owner;
    for (const auto &id : found->second) {
        const auto &record = records_.at(id);
        if (now >= record.expires) {
            // A stale competing observation cannot prove that owner went away.
            return {Status::Unknown, std::nullopt};
        }
        if (owner && *owner != id.process) {
            return {Status::Ambiguous, std::nullopt};
        }
        owner = id.process;
    }
    return {Status::Observed, owner};
}
std::optional<FlowIdentity> FlowIndex::lookupFlow(PacketTuple tuple, Time now) const {
    if (lookup(tuple, now).status != Status::Observed) { return std::nullopt; }
    const auto found = tuples_.find(canonical(tuple));
    if (found == tuples_.end() || found->second.size() != 1) { return std::nullopt; }
    return *found->second.begin();
}
void FlowIndex::expire(Time now) {
    for (const auto &[id, record] : records_) {
        (void)id;
        // Forgetting a live owner can hide a collision; forgetting a tombstone
        // can resurrect a delayed open. Both require a new observation epoch.
        if (now >= record.expires) {
            invalidate();
            return;
        }
    }
}
void FlowIndex::invalidate() {
    reliable_ = false;
    records_.clear();
    tuples_.clear();
}
void FlowIndex::reset() {
    invalidate();
    reliable_ = true;
}
} // namespace skewer::traffic
