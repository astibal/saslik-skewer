#pragma once
#include "flow_observer.hpp"
#include "flow_index.hpp"

namespace skewer::windows::traffic {
// Normalize WinDivert's textual endpoints to the portable packet representation.
// Invalid addresses/family/protocol yield no tuple, never a guessed conversion.
std::optional<skewer::traffic::PacketTuple> flowTuple(const FlowEvent& event);
skewer::traffic::FlowIndex::Update recordFlow(skewer::traffic::FlowIndex& index, const FlowEvent& event,
                                              skewer::traffic::FlowIndex::Time now);

// Separate diagnostic epoch for CONNECT/CLOSE. CLOSE is keyed by the kernel
// endpoint identity; its address fields need not repeat the original tuple.
// Unknown close, missing events and ambiguity never grant packet ownership.
class SocketAttemptIndex final {
public:
    using Index = skewer::traffic::FlowIndex;
    Index::Update observe(const FlowEvent& event, Index::Time now);
    Index::Match lookup(skewer::traffic::PacketTuple tuple, Index::Time now) const;
    std::optional<skewer::traffic::FlowIdentity> lookupFlow(skewer::traffic::PacketTuple tuple, Index::Time now) const;
    void invalidate();

private:
    Index index_;
    // Same fixed 4096-entry limit as index_; closed records remain tombstones.
    std::map<skewer::traffic::FlowIdentity, skewer::traffic::PacketTuple> tuples_;
};

// UDP BIND/CLOSE ownership before the first datagram reaches NETWORK. Remote
// addresses are deliberately absent; the owner table must independently
// corroborate the local bind and reject wildcard/dual-stack competition.
class UdpBindIndex final {
public:
    void observe(const FlowEvent& event);
    std::optional<skewer::traffic::FlowIdentity> lookup(skewer::traffic::PacketTuple tuple) const;
    void invalidate();

private:
    struct Bind { bool ipv6{}; std::array<std::uint8_t, 16> address{}; std::uint16_t port{}; };
    std::map<skewer::traffic::FlowIdentity, Bind> binds_;
    bool reliable_{true};
};

// Retains the authenticated process handle and a CONNECT/CLOSE index together.
// Cancellation, exit and read errors permanently invalidate this epoch. This
// remains diagnostic evidence, never a conversion to PacketOwner::Unique.
class TrackedSocketObserver final {
public:
    TrackedSocketObserver(const std::wstring& dll, ProcessKey process);
    TrackedSocketObserver(const std::wstring& dll, std::unique_ptr<ProcessTarget> process);
    FlowObserver::Result next(HANDLE cancellation, DWORD timeout_ms);
    skewer::traffic::FlowIndex::Match lookup(skewer::traffic::PacketTuple tuple);
    std::optional<skewer::traffic::FlowIdentity> lookupFlow(skewer::traffic::PacketTuple tuple);
    std::optional<skewer::traffic::FlowIdentity> lookupUdpBind(skewer::traffic::PacketTuple tuple);

private:
    FlowObserver observer_;
    SocketAttemptIndex index_;
    UdpBindIndex udp_;
};

// One consumer owns both observer and index. No automatic epoch reset: once
// context is lost, correlation remains unreliable for this observer lifetime.
class TrackedFlowObserver final {
public:
    TrackedFlowObserver(const std::wstring& dll, ProcessKey process);
    TrackedFlowObserver(const std::wstring& dll, std::unique_ptr<ProcessTarget> process);
    FlowObserver::Result next(HANDLE cancellation, DWORD timeout_ms);
    skewer::traffic::FlowIndex::Match lookup(skewer::traffic::PacketTuple tuple);

private:
    FlowObserver observer_;
    skewer::traffic::FlowIndex index_;
};
} // namespace skewer::windows::traffic
