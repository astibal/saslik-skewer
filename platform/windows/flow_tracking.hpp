#pragma once
#include "flow_observer.hpp"
#include "flow_index.hpp"

namespace skewer::windows::traffic {
// Normalize WinDivert's textual endpoints to the portable packet representation.
// Invalid addresses/family/protocol yield no tuple, never a guessed conversion.
std::optional<skewer::traffic::PacketTuple> flowTuple(const FlowEvent& event);
skewer::traffic::FlowIndex::Update recordFlow(skewer::traffic::FlowIndex& index, const FlowEvent& event,
                                              skewer::traffic::FlowIndex::Time now);

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
