#pragma once
#include "flow_index.hpp"
#include <algorithm>
#include <span>
#include <stdexcept>

namespace skewer::traffic {
// Corroboration is not authority: snapshots and socket events are non-atomic.
// Keep this type separate from PacketOwner so callers cannot accidentally
// release packets merely because independent diagnostic sources agree.
enum class OwnerEvidence {
    Corroborated,
    MissingLifecycle,
    ConflictingLifecycle,
    MissingSnapshotOwner,
    CompetingOwner,
    UnknownOwner,
    StaleSnapshot,
    Unreliable
};

inline OwnerEvidence assessOwnerEvidence(ProcessIdentity selected, FlowIndex::Match lifecycle,
                                         std::span<const std::uint32_t> candidates, bool unknown_owner,
                                         FlowIndex::Time started, FlowIndex::Time completed,
                                         FlowIndex::Time now, FlowIndex::Clock::duration maximum_age) {
    if (!selected.pid || !selected.created || maximum_age <= FlowIndex::Clock::duration::zero()) {
        throw std::invalid_argument("Invalid ownership evidence policy");
    }
    if (lifecycle.status == FlowIndex::Status::Unreliable || completed < started || now < completed) {
        return OwnerEvidence::Unreliable;
    }
    // Include collection duration: a newly completed but slow table read is
    // not fresh. A boundary-age snapshot is already expired.
    if (now - started >= maximum_age) {
        return OwnerEvidence::StaleSnapshot;
    }
    if (lifecycle.status == FlowIndex::Status::Unknown) {
        return OwnerEvidence::MissingLifecycle;
    }
    if (lifecycle.status == FlowIndex::Status::Ambiguous) {
        return OwnerEvidence::CompetingOwner;
    }
    if (!lifecycle.process) {
        return OwnerEvidence::Unreliable;
    }
    if (*lifecycle.process != selected) {
        return OwnerEvidence::ConflictingLifecycle;
    }
    if (unknown_owner || std::find(candidates.begin(), candidates.end(), 0) != candidates.end()) {
        return OwnerEvidence::UnknownOwner;
    }
    if (std::any_of(candidates.begin(), candidates.end(), [&](auto pid) { return pid != selected.pid; })) {
        return OwnerEvidence::CompetingOwner;
    }
    return candidates.empty() ? OwnerEvidence::MissingSnapshotOwner : OwnerEvidence::Corroborated;
}
} // namespace skewer::traffic
