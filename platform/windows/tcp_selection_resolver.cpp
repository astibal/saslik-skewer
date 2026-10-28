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
    if (!flow) {
        return {OwnerEvidence::MissingLifecycle, std::nullopt};
    }
    const auto snapshot = captureTcpOwners();
    // Table queries may block. Drain closes again and require the same socket
    // identity, not merely the same process or local source port.
    if (!drain(cancel) || observer_.lookupFlow(tuple) != flow) {
        return {};
    }
    const auto candidates = tcpOwnerCandidates(snapshot.rows, tuple);
    const auto evidence = skewer::traffic::assessOwnerEvidence(
        flow->process, observer_.lookup(tuple), candidates, false, snapshot.started, snapshot.completed,
        TcpOwnerSnapshot::Clock::now(), std::chrono::milliseconds(250));
    return {evidence, evidence == OwnerEvidence::Corroborated ? flow : std::nullopt};
}
} // namespace skewer::windows::traffic
