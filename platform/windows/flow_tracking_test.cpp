#include "flow_tracking.hpp"
#include <iostream>
#include <stdexcept>

namespace {
using namespace skewer::windows::traffic;
using skewer::traffic::FlowIndex;
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
FlowEvent sample() {
    FlowEvent event;
    event.process = {42, 100};
    event.endpoint_id = 12;
    event.timestamp_ticks = 10;
    event.protocol = 6;
    event.local = {"192.0.2.1", 12345};
    event.remote = {"198.51.100.2", 443};
    return event;
}
void testConversion() {
    auto event = sample();
    auto tuple = flowTuple(event);
    require(tuple && !tuple->ipv6 && tuple->source[0] == 192 && tuple->source[3] == 1 &&
                tuple->source[4] == 0 && tuple->destination[0] == 198 && tuple->destination[3] == 2 &&
                tuple->source_port == 12345 && tuple->destination_port == 443,
            "IPv4 bytes/ports changed");
    event.ipv6 = true;
    require(!flowTuple(event), "Family mismatch accepted");
    event.local.address = "2001:db8::1";
    event.remote.address = "2001:db8::abcd";
    tuple = flowTuple(event);
    require(tuple && tuple->ipv6 && tuple->source[0] == 0x20 && tuple->source[1] == 1 &&
                tuple->source[15] == 1 && tuple->destination[14] == 0xab && tuple->destination[15] == 0xcd,
            "IPv6 byte order changed");
    event.local.address = "::ffff:192.0.2.1";
    tuple = flowTuple(event);
    require(tuple && tuple->ipv6, "Mapped address lost IPv6 identity");
    for (const auto bad : {"", "not-an-ip", "::1%4", "::1 trailing"}) {
        event.local.address = bad;
        require(!flowTuple(event), "Invalid address accepted");
    }
    event = sample();
    event.local.address += std::string("\0suffix", 7);
    require(!flowTuple(event), "Embedded NUL accepted");
    event = sample();
    event.protocol = 1;
    require(!flowTuple(event), "Unsupported protocol accepted");
}
void testUpdates() {
    FlowIndex index;
    auto event = sample();
    const auto tuple = *flowTuple(event);
    require(recordFlow(index, event, {}) == FlowIndex::Update::Applied, "Open not recorded");
    require(index.lookup(tuple, {}).status == FlowIndex::Status::Observed, "Owner missing");
    event.kind = FlowEvent::Kind::Deleted;
    event.timestamp_ticks++;
    recordFlow(index, event, {});
    require(index.lookup(tuple, {}).status == FlowIndex::Status::Unknown, "Deleted flow survived");
    event.timestamp_ticks = -1;
    require(recordFlow(index, event, {}) == FlowIndex::Update::Unreliable, "Negative time accepted");
    index.reset();
    event = sample();
    event.kind = FlowEvent::Kind::ConnectAttempt;
    require(recordFlow(index, event, {}) == FlowIndex::Update::Unreliable &&
                index.lookup(tuple, {}).status == FlowIndex::Status::Unreliable,
            "CONNECT attempt was accepted as an established flow");
    index.reset();
    event = sample();
    event.remote.address = "invalid";
    recordFlow(index, event, {});
    require(index.lookup(tuple, {}).status == FlowIndex::Status::Unreliable, "Bad conversion retained index");
}
void testSocketLifecycle() {
    SocketAttemptIndex index;
    auto event = sample();
    event.kind = FlowEvent::Kind::ConnectAttempt;
    const auto tuple = *flowTuple(event);
    require(index.observe(event, {}) == FlowIndex::Update::Applied, "CONNECT not recorded");
    event.kind = FlowEvent::Kind::SocketClosed;
    event.timestamp_ticks = 9;
    event.local.address.clear();
    event.remote.address.clear();
    require(index.observe(event, {}) == FlowIndex::Update::Ignored &&
                index.lookup(tuple, {}).status == FlowIndex::Status::Observed,
            "Old CLOSE removed attempt");
    event.timestamp_ticks = 11;
    require(index.observe(event, {}) == FlowIndex::Update::Applied &&
                index.lookup(tuple, {}).status == FlowIndex::Status::Unknown,
            "CLOSE retained attempt");
    event = sample();
    event.kind = FlowEvent::Kind::ConnectAttempt;
    event.timestamp_ticks = 12;
    require(index.observe(event, {}) == FlowIndex::Update::Ignored, "Closed endpoint resurrected");
    SocketAttemptIndex missing;
    event.kind = FlowEvent::Kind::SocketClosed;
    require(missing.observe(event, {}) == FlowIndex::Update::Unreliable, "Unknown CLOSE guessed owner");
    event.kind = FlowEvent::Kind::ConnectAttempt;
    require(missing.observe(event, {}) == FlowIndex::Update::Unreliable, "Lost epoch recovered silently");
    SocketAttemptIndex ambiguous;
    ambiguous.observe(event, {});
    ++event.process.pid;
    ambiguous.observe(event, {});
    require(ambiguous.lookup(tuple, {}).status == FlowIndex::Status::Ambiguous,
            "Shared tuple chose an owner");
}
void testUdpBindLifecycle() {
    UdpBindIndex index;
    auto event = sample();
    event.protocol = 17;
    event.kind = FlowEvent::Kind::SocketBound;
    // WinDivert 2.2 uses this spelling for an IPv4 wildcard BIND.
    event.local = {"::", 0};
    index.observe(event);

    skewer::traffic::PacketTuple tuple;
    tuple.protocol = 17;
    tuple.source = {192, 0, 2, 1};
    tuple.source_port = 53000;
    require(!index.lookup(tuple), "Port-zero UDP bind was treated as assigned");

    event.kind = FlowEvent::Kind::ConnectAttempt;
    event.local.port = tuple.source_port;
    index.observe(event);
    const auto owner = index.lookup(tuple);
    require(owner && owner->process == skewer::traffic::ProcessIdentity{42, 100},
            "Wildcard UDP bind did not match its assigned local port");
    auto other = tuple;
    ++other.source_port;
    require(!index.lookup(other), "UDP bind matched another local port");

    auto competing = event;
    competing.process.pid = 43;
    competing.endpoint_id = 13;
    index.observe(competing);
    require(!index.lookup(tuple), "Competing UDP binds selected an owner");
    competing.kind = FlowEvent::Kind::SocketClosed;
    index.observe(competing);
    require(index.lookup(tuple) == owner, "UDP CLOSE removed another endpoint");

    event.kind = FlowEvent::Kind::SocketClosed;
    index.observe(event);
    require(!index.lookup(tuple), "Closed UDP bind retained ownership");

    UdpBindIndex malformed;
    event.kind = FlowEvent::Kind::SocketBound;
    event.local = {"not-an-address", tuple.source_port};
    malformed.observe(event);
    require(!malformed.lookup(tuple), "Malformed UDP bind retained a usable epoch");
}
} // namespace
int main() {
    try {
        testConversion();
        testUpdates();
        testSocketLifecycle();
        testUdpBindLifecycle();
        std::cout << "PASS: Windows flow normalization and index updates (no driver loaded)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
