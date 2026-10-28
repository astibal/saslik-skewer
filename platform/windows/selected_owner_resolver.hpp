#pragma once
#include "flow_tracking.hpp"
#include "tcp_owners.hpp"
#include "udp_owners.hpp"
#include "../traffic/owner_evidence.hpp"

namespace skewer::windows::traffic {
// Lab-grade corroboration of a selected TCP or connected UDP socket. Socket
// events and owner tables are non-atomic; this is deliberately not a security
// authority. Unconnected UDP has no remote lifecycle tuple and remains held.
class SelectedOwnerResolver final {
public:
    enum class Disposition { Hold, Tunnel, Direct };
    struct Result {
        skewer::traffic::OwnerEvidence evidence{skewer::traffic::OwnerEvidence::Unreliable};
        std::optional<skewer::traffic::FlowIdentity> flow;
        Disposition disposition{Disposition::Hold};
    };
    SelectedOwnerResolver(const std::wstring& dll, std::unique_ptr<ProcessTarget> target);
    Result resolve(skewer::traffic::PacketTuple tuple, HANDLE cancel);

private:
    bool drain(HANDLE cancel);
    bool awaitTcpFlow(skewer::traffic::PacketTuple tuple, HANDLE cancel);
    std::optional<skewer::traffic::FlowIdentity> lookupFlow(skewer::traffic::PacketTuple tuple);
    skewer::traffic::FlowIndex::Match lookup(skewer::traffic::PacketTuple tuple);
    ProcessKey target_;
    TrackedSocketObserver observer_;
};
} // namespace skewer::windows::traffic
