#include <winsock2.h>
#include "selected_owner_resolver.hpp"

namespace skewer::windows::traffic {
SelectedOwnerResolver::SelectedOwnerResolver(const std::wstring& dll,
                                             std::unique_ptr<ProcessTarget> target)
    : target_(target ? target->key() : ProcessKey{}), observer_(dll, std::move(target)) {}

bool SelectedOwnerResolver::drain(HANDLE cancel) {
    // Bounded work per held packet. Backlog is not permission to route using an
    // older CONNECT while a CLOSE may still be waiting in the driver queue.
    for (unsigned i = 0; i < 64; ++i) {
        const auto event = observer_.next(cancel, 0);
        if (event.status == FlowObserver::Status::Timeout) return true;
        if (event.status != FlowObserver::Status::Event) return false;
    }
    return false;
}

bool SelectedOwnerResolver::awaitSelectedFlow(skewer::traffic::PacketTuple tuple, HANDLE cancel) {
    // NETWORK can deliver the first TCP or UDP packet a few milliseconds
    // before SOCKET delivers its CONNECT metadata. Wait only for a selected
    // owner candidate; unrelated traffic must not make capture a delay line.
    for (unsigned i = 0; i < 20; ++i) {
        const auto event = observer_.next(cancel, 5);
        if (event.status != FlowObserver::Status::Event &&
            event.status != FlowObserver::Status::Timeout) return false;
        if (observer_.lookupFlow(tuple)) return true;
    }
    return false;
}

std::optional<skewer::traffic::FlowIdentity>
SelectedOwnerResolver::lookupFlow(skewer::traffic::PacketTuple tuple) {
    return tuple.protocol == IPPROTO_TCP ? observer_.lookupFlow(tuple) : observer_.lookupUdpBind(tuple);
}
skewer::traffic::FlowIndex::Match SelectedOwnerResolver::lookup(skewer::traffic::PacketTuple tuple) {
    if (tuple.protocol == IPPROTO_TCP) return observer_.lookup(tuple);
    const auto flow = observer_.lookupUdpBind(tuple);
    return flow ? skewer::traffic::FlowIndex::Match{skewer::traffic::FlowIndex::Status::Observed,
                                                    flow->process}
                : skewer::traffic::FlowIndex::Match{};
}

SelectedOwnerResolver::Result SelectedOwnerResolver::resolve(skewer::traffic::PacketTuple tuple,
                                                              HANDLE cancel) {
    using skewer::traffic::OwnerEvidence;
    if ((tuple.protocol != IPPROTO_TCP && tuple.protocol != IPPROTO_UDP) ||
        !drain(cancel)) return {};
    auto flow = lookupFlow(tuple);
    std::vector<std::uint32_t> candidates;
    bool unknown_owner{};
    bool unique_udp_bind{};
    TcpOwnerSnapshot::Clock::time_point started, completed;
    const auto captureOwners = [&] {
        unknown_owner = false;
        if (tuple.protocol == IPPROTO_TCP) {
            const auto snapshot = captureTcpOwners();
            candidates = tcpOwnerCandidates(snapshot.rows, tuple);
            started = snapshot.started;
            completed = snapshot.completed;
        } else {
            const auto snapshot = captureUdpOwners();
            auto owners = udpOwnerCandidates(snapshot.rows, tuple);
            unique_udp_bind = owners.uniqueBind();
            candidates = std::move(owners.pids);
            unknown_owner = owners.unknown_owner;
            started = snapshot.started;
            completed = snapshot.completed;
        }
    };
    captureOwners();
    const bool selected_candidate = !unknown_owner &&
        std::find(candidates.begin(), candidates.end(), target_.pid) != candidates.end();
    if (!flow && selected_candidate && awaitSelectedFlow(tuple, cancel)) {
        flow = lookupFlow(tuple);
        captureOwners();
    }
    // Table queries may block. Drain closes again and require the same socket
    // identity, not merely the same process or local source port.
    if (!drain(cancel) || lookupFlow(tuple) != flow) return {};
    const auto now = TcpOwnerSnapshot::Clock::now();
    const auto lifecycle = lookup(tuple);
    if (completed < started || now < completed || now - started >= std::chrono::milliseconds(250) ||
        lifecycle.status == skewer::traffic::FlowIndex::Status::Unreliable) return {};
    if (!flow) {
        // An unrelated flow may continue directly only when the owner snapshot
        // positively excludes the selection. Missing/ambiguous evidence holds.
        const bool unrelated = !unknown_owner && !candidates.empty() &&
            std::all_of(candidates.begin(), candidates.end(),
                        [&](auto pid) { return pid && pid != target_.pid; });
        return {OwnerEvidence::MissingLifecycle, std::nullopt,
                unrelated && lifecycle.status == skewer::traffic::FlowIndex::Status::Unknown
                    ? Disposition::Direct : Disposition::Hold};
    }
    // A single PID can own multiple competing binds. The observer may have
    // missed a bind created before attachment, so PID de-duplication must not
    // turn an ambiguous owner-table snapshot into permission to tunnel.
    if (tuple.protocol == IPPROTO_UDP && !unique_udp_bind) {
        return {OwnerEvidence::ConflictingLifecycle, std::nullopt, Disposition::Hold};
    }
    const auto evidence = skewer::traffic::assessOwnerEvidence(
        flow->process, lookup(tuple), candidates, unknown_owner, started, completed, now,
        std::chrono::milliseconds(250));
    return {evidence, evidence == OwnerEvidence::Corroborated ? flow : std::nullopt,
            evidence == OwnerEvidence::Corroborated ? Disposition::Tunnel : Disposition::Hold};
}
} // namespace skewer::windows::traffic
