#pragma once
#include "flow_tracking.hpp"
#include "tcp_owners.hpp"
#include "../traffic/owner_evidence.hpp"

namespace skewer::windows::traffic {
// Lab-grade corroboration of a selected TCP socket. Events and owner tables are
// non-atomic; this is deliberately not PacketOwner::Unique or a security claim.
// Caller keeps captures held while evidence is missing, never falls back direct.
class TcpSelectionResolver final {
public:
    enum class Disposition { Hold, Tunnel, Direct };
    struct Result {
        skewer::traffic::OwnerEvidence evidence{skewer::traffic::OwnerEvidence::Unreliable};
        std::optional<skewer::traffic::FlowIdentity> flow;
        Disposition disposition{Disposition::Hold};
    };
    TcpSelectionResolver(const std::wstring& dll, std::unique_ptr<ProcessTarget> target)
        : target_(target ? target->key() : ProcessKey{}), observer_(dll, std::move(target)) {}
    Result resolve(skewer::traffic::PacketTuple tuple, HANDLE cancel);

private:
    bool drain(HANDLE cancel);
    ProcessKey target_;
    TrackedSocketObserver observer_;
};
} // namespace skewer::windows::traffic
