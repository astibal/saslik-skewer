#include "tcp_selection_resolver.hpp"

namespace skewer::windows::traffic {
bool TcpSelectionResolver::drain(HANDLE cancel) {
    // Bounded work per held packet. Backlog is not permission to route using an
    // older CONNECT while a CLOSE may still be waiting in the driver queue.
    for (unsigned i = 0; i < 64; ++i) {
        const auto event = observer_.next(cancel, 0);
        if (event.status == FlowObserver::Status::Timeout) {
            return true;
        }
        if (event.status != FlowObserver::Status::Event) {
            return false;
        }
    }
    return false;
}
TcpSelectionResolver::Result TcpSelectionResolver::resolve(skewer::traffic::PacketTuple tuple,
                                                           HANDLE cancel) {
    using skewer::traffic::OwnerEvidence;
    if (tuple.protocol != 6 || !drain(cancel)) {
        return {};
    }
    const auto flow = observer_.lookupFlow(tuple);
    const auto snapshot = captureTcpOwners();
    // Table queries may block. Drain closes again and require the same socket
    // identity, not merely the same process or local source port.
    if (!drain(cancel) || observer_.lookupFlow(tuple) != flow) {
        return {};
    }
    const auto candidates = tcpOwnerCandidates(snapshot.rows, tuple);
    const auto now = TcpOwnerSnapshot::Clock::now();
    const auto lifecycle = observer_.lookup(tuple);
    if (snapshot.completed < snapshot.started || now < snapshot.completed ||
        now - snapshot.started >= std::chrono::milliseconds(250) ||
        lifecycle.status == skewer::traffic::FlowIndex::Status::Unreliable) {
        return {};
    }
    if (!flow) {
        // Explicit lab policy, not atomic attribution. An absent/unknown owner
        // or any selected-PID candidate must never produce a direct bypass.
        const bool unrelated = excludesSelectedTcpOwner(candidates, target_.pid);
        return {OwnerEvidence::MissingLifecycle, std::nullopt,
                unrelated && lifecycle.status == skewer::traffic::FlowIndex::Status::Unknown
                    ? Disposition::Direct
                    : Disposition::Hold};
    }
    const auto evidence = skewer::traffic::assessOwnerEvidence(
        flow->process, observer_.lookup(tuple), candidates, false, snapshot.started, snapshot.completed,
        TcpOwnerSnapshot::Clock::now(), std::chrono::milliseconds(250));
    return {evidence, evidence == OwnerEvidence::Corroborated ? flow : std::nullopt,
            evidence == OwnerEvidence::Corroborated ? Disposition::Tunnel : Disposition::Hold};
}
} // namespace skewer::windows::traffic
