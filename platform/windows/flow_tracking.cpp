#include <winsock2.h>
#include <ws2tcpip.h>
#include "flow_tracking.hpp"
#include <algorithm>
#include <stdexcept>

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

void UdpBindIndex::observe(const FlowEvent& event) {
    if (event.protocol != IPPROTO_UDP) return;
    const skewer::traffic::FlowIdentity id{{event.process.pid, event.process.created}, event.endpoint_id};
    if (event.kind == FlowEvent::Kind::SocketClosed) {
        binds_.erase(id);
        return;
    }
    if (event.kind != FlowEvent::Kind::SocketBound && event.kind != FlowEvent::Kind::ConnectAttempt) return;
    // bind(port=0) reports the requested value, not the assigned ephemeral
    // port. A later CONNECT carries the usable local endpoint.
    if (!event.local.port) return;
    if (event.local.address.find('\0') != std::string::npos ||
        (binds_.size() >= 4096 && !binds_.contains(id))) {
        invalidate();
        return;
    }
    Bind bind;
    bind.ipv6 = event.ipv6;
    bind.port = event.local.port;
    if (InetPtonA(bind.ipv6 ? AF_INET6 : AF_INET, event.local.address.c_str(), bind.address.data()) != 1) {
        invalidate();
        return;
    }
    binds_.insert_or_assign(id, bind);
}

std::optional<skewer::traffic::FlowIdentity>
UdpBindIndex::lookup(PacketTuple tuple) const {
    if (!reliable_ || tuple.protocol != IPPROTO_UDP || !tuple.source_port) return std::nullopt;
    std::optional<skewer::traffic::FlowIdentity> result;
    for (const auto& [identity, bind] : binds_) {
        if (bind.ipv6 != tuple.ipv6 || bind.port != tuple.source_port) continue;
        const auto size = bind.ipv6 ? 16U : 4U;
        const bool wildcard = std::all_of(bind.address.begin(), bind.address.begin() + size,
                                          [](auto byte) { return byte == 0; });
        if (!wildcard && !std::equal(bind.address.begin(), bind.address.begin() + size,
                                     tuple.source.begin())) continue;
        if (result && *result != identity) return std::nullopt;
        result = identity;
    }
    return result;
}

void UdpBindIndex::invalidate() {
    reliable_ = false;
    binds_.clear();
}
std::optional<skewer::traffic::FlowIdentity> SocketAttemptIndex::lookupFlow(PacketTuple tuple, Index::Time now) const {
    return index_.lookupFlow(tuple, now);
}
std::optional<skewer::traffic::FlowIdentity> TrackedSocketObserver::lookupFlow(PacketTuple tuple) {
    try {
        if (!observer_.targetRunning()) { index_.invalidate(); }
        return index_.lookupFlow(tuple, FlowIndex::Clock::now());
    } catch (...) { index_.invalidate(); throw; }
}

TrackedSocketObserver::TrackedSocketObserver(const std::wstring& dll, ProcessKey process)
    : TrackedSocketObserver(dll, std::make_unique<ProcessTarget>(process)) {}

TrackedSocketObserver::TrackedSocketObserver(const std::wstring& dll, std::unique_ptr<ProcessTarget> process)
    : observer_(dll, std::move(process), FlowObserver::Mode::SocketLifecycle) {}

FlowObserver::Result TrackedSocketObserver::next(HANDLE cancellation, DWORD timeout_ms) {
    try {
        auto result = observer_.next(cancellation, timeout_ms);
        if (result.status == FlowObserver::Status::Event) {
            if (!result.event) {
                index_.invalidate();
                throw std::runtime_error("Socket observer returned an event without metadata");
            }
            if (result.event->protocol == IPPROTO_TCP) index_.observe(*result.event, FlowIndex::Clock::now());
            else udp_.observe(*result.event);
        } else if (result.status != FlowObserver::Status::Timeout) {
            index_.invalidate();
            udp_.invalidate();
        }
        return result;
    } catch (...) {
        index_.invalidate();
        udp_.invalidate();
        throw;
    }
}

std::optional<skewer::traffic::FlowIdentity>
TrackedSocketObserver::lookupUdpBind(PacketTuple tuple) {
    try {
        if (!observer_.targetRunning()) udp_.invalidate();
        return udp_.lookup(tuple);
    } catch (...) { udp_.invalidate(); throw; }
}

FlowIndex::Match TrackedSocketObserver::lookup(PacketTuple tuple) {
    try {
        if (!observer_.targetRunning()) {
            index_.invalidate();
        }
        return index_.lookup(tuple, FlowIndex::Clock::now());
    } catch (...) {
        index_.invalidate();
        throw;
    }
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
