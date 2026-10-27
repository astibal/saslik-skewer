#include <winsock2.h>
#include <ws2tcpip.h>
#include "flow_tracking.hpp"

namespace skewer::windows::traffic {
using skewer::traffic::FlowIndex;
using skewer::traffic::PacketTuple;

std::optional<PacketTuple> flowTuple(const FlowEvent& event) {
    if (event.protocol != 6 && event.protocol != 17) {
        return std::nullopt;
    }
    // Reject embedded NUL rather than letting InetPton accept only a prefix.
    if (event.local.address.find('\0') != std::string::npos ||
        event.remote.address.find('\0') != std::string::npos) {
        return std::nullopt;
    }
    PacketTuple tuple;
    tuple.ipv6 = event.ipv6;
    tuple.protocol = event.protocol;
    tuple.source_port = event.local.port;
    tuple.destination_port = event.remote.port;
    const auto family = event.ipv6 ? AF_INET6 : AF_INET;
    // InetPton writes network-order bytes and does not require WSAStartup.
    if (InetPtonA(family, event.local.address.c_str(), tuple.source.data()) != 1 ||
        InetPtonA(family, event.remote.address.c_str(), tuple.destination.data()) != 1) {
        return std::nullopt;
    }
    return tuple;
}

FlowIndex::Update recordFlow(FlowIndex& index, const FlowEvent& event, FlowIndex::Time now) {
    const auto tuple = flowTuple(event);
    if (!tuple || event.timestamp_ticks <= 0 ||
        (event.kind != FlowEvent::Kind::Established && event.kind != FlowEvent::Kind::Deleted)) {
        index.invalidate();
        return FlowIndex::Update::Unreliable;
    }
    index.expire(now);
    return index.observe({{event.process.pid, event.process.created}, event.endpoint_id}, *tuple,
                         event.kind == FlowEvent::Kind::Established,
                         static_cast<std::uint64_t>(event.timestamp_ticks), now);
}

TrackedFlowObserver::TrackedFlowObserver(const std::wstring& dll, ProcessKey process)
    : TrackedFlowObserver(dll, std::make_unique<ProcessTarget>(process)) {}

SocketAttemptIndex::Index::Update SocketAttemptIndex::observe(const FlowEvent& event, Index::Time now) {
    if (event.timestamp_ticks <= 0 ||
        (event.kind != FlowEvent::Kind::ConnectAttempt && event.kind != FlowEvent::Kind::SocketClosed)) {
        invalidate();
        return Index::Update::Unreliable;
    }
    const skewer::traffic::FlowIdentity id{{event.process.pid, event.process.created}, event.endpoint_id};
    const bool opening = event.kind == FlowEvent::Kind::ConnectAttempt;
    auto tuple = flowTuple(event);
    const auto found = tuples_.find(id);
    if (!opening) {
        if (found == tuples_.end()) {
            // A missed CONNECT or reordered CLOSE loses this observation epoch.
            // Do not guess a tuple from incomplete close metadata.
            invalidate();
            return Index::Update::Unreliable;
        }
        tuple = found->second;
    }
    if (!tuple) {
        invalidate();
        return Index::Update::Unreliable;
    }
    try {
        index_.expire(now);
        const auto result = index_.observe(id, *tuple, opening, event.timestamp_ticks, now);
        if (result == Index::Update::Applied && opening) {
            tuples_.insert_or_assign(id, *tuple);
        }
        return result;
    } catch (...) {
        invalidate();
        throw;
    }
}

SocketAttemptIndex::Index::Match SocketAttemptIndex::lookup(PacketTuple tuple, Index::Time now) const {
    return index_.lookup(tuple, now);
}

void SocketAttemptIndex::invalidate() {
    index_.invalidate();
    tuples_.clear();
}

TrackedFlowObserver::TrackedFlowObserver(const std::wstring& dll, std::unique_ptr<ProcessTarget> process)
    : observer_(dll, std::move(process)) {}

FlowObserver::Result TrackedFlowObserver::next(HANDLE cancellation, DWORD timeout_ms) {
    try {
        auto result = observer_.next(cancellation, timeout_ms);
        const auto now = FlowIndex::Clock::now();
        if (result.status == FlowObserver::Status::Event) {
            recordFlow(index_, *result.event, now);
        } else if (result.status == FlowObserver::Status::Timeout) {
            index_.expire(now);
        } else {
            index_.invalidate(); // Cancellation/exit must not leave a usable owner.
        }
        return result;
    } catch (...) {
        index_.invalidate();
        throw;
    }
}
FlowIndex::Match TrackedFlowObserver::lookup(PacketTuple tuple) {
    try {
        if (!observer_.targetRunning()) {
            index_.invalidate();
        }
    } catch (...) {
        index_.invalidate();
        throw;
    }
    const auto now = FlowIndex::Clock::now();
    index_.expire(now);
    return index_.lookup(tuple, now);
}
} // namespace skewer::windows::traffic
