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
} // namespace
int main() {
    try {
        testConversion();
        testUpdates();
        std::cout << "PASS: Windows flow normalization and index updates (no driver loaded)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
