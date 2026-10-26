#include "flow_index.hpp"
#include <iostream>
#include <stdexcept>

using namespace skewer::traffic;
namespace {
using Status = FlowIndex::Status;
using Update = FlowIndex::Update;
const FlowIndex::Time start{};
const FlowIdentity first{{42, 100}, 1};
const FlowIdentity second{{43, 100}, 2};
PacketTuple packet() {
    PacketTuple tuple;
    tuple.protocol = 6;
    tuple.source[0] = 10;
    tuple.destination[0] = 20;
    tuple.source_port = 12345;
    tuple.destination_port = 443;
    return tuple;
}
void require(bool ok, const char *message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
void match(const FlowIndex &index, PacketTuple tuple, Status expected, FlowIndex::Time now = start) {
    const auto result = index.lookup(tuple, now);
    require(result.status == expected, "Unexpected correlation status");
    require(result.process.has_value() == (expected == Status::Observed), "Owner/result invariant");
}
void basic() {
    FlowIndex index;
    const auto tuple = packet();
    match(index, tuple, Status::Unknown);
    require(index.observe(first, tuple, true, 10, start) == Update::Applied, "Open failed");
    match(index, tuple, Status::Observed);
    match(index, tuple.reversed(), Status::Observed);
    require(index.lookup(tuple, start).process == first.process, "Wrong identity");
    auto different = tuple;
    different.protocol = 17;
    match(index, different, Status::Unknown);
    different = tuple;
    different.ipv6 = true;
    match(index, different, Status::Unknown);
    index.observe(second, tuple, true, 11, start);
    match(index, tuple, Status::Ambiguous);
    index.observe(second, tuple, false, 12, start);
    match(index, tuple, Status::Observed);
    require(index.observe(second, tuple, true, 11, start) == Update::Ignored, "Stale open resurrected");
    require(index.observe(second, tuple, true, 13, start) == Update::Ignored, "Closed endpoint resurrected");
    index.observe(first, tuple, false, 14, start);
    match(index, tuple, Status::Unknown);
}
void identityAndOrdering() {
    FlowIndex index;
    const auto tuple = packet();
    index.observe(first, tuple, true, 10, start);
    const FlowIdentity sameProcess{first.process, 99};
    index.observe(sameProcess, tuple.reversed(), true, 10, start);
    match(index, tuple, Status::Observed); // Multiple sockets, one owner.
    const FlowIdentity recycledPid{{first.process.pid, first.process.created + 1}, 100};
    index.observe(recycledPid, tuple, true, 11, start);
    match(index, tuple, Status::Ambiguous);
    index.reset();
    index.observe(first, tuple, false, 20, start); // Deletion arrived first.
    index.observe(first, tuple, true, 19, start);
    match(index, tuple, Status::Unknown);
    index.reset();
    index.observe(first, tuple, true, 10, start);
    index.observe(first, tuple, false, 9, start);
    match(index, tuple, Status::Observed);
    index.observe(first, tuple, false, 10, start); // Equal timestamps: closure wins.
    match(index, tuple, Status::Unknown);
    auto changed = tuple;
    changed.destination_port++;
    require(index.observe(first, changed, true, 11, start) == Update::Unreliable, "Endpoint mutated");
    match(index, tuple, Status::Unreliable);
}
void boundsAndLoss() {
    const auto tuple = packet();
    FlowIndex index(1, std::chrono::seconds(1));
    index.observe(first, tuple, true, 10, start);
    require(index.observe(second, tuple, true, 11, start) == Update::Unreliable, "Overflow not latched");
    require(index.size() == 0, "Overflow retained records");
    match(index, tuple, Status::Unreliable);
    require(index.observe(first, tuple, true, 12, start) == Update::Unreliable, "Loss auto-recovered");
    index.reset();
    index.observe(first, tuple, true, 10, start);
    const auto later = start + std::chrono::seconds(1);
    match(index, tuple, Status::Unknown, later);
    index.expire(later);
    match(index, tuple, Status::Unreliable, later);
    index.reset();
    index.observe(first, tuple, false, 10, start);
    index.expire(later);
    require(index.observe(first, tuple, true, 9, later) == Update::Unreliable,
            "Expired tombstone resurrected");
    index.reset();
    require(index.observe({}, tuple, true, 10, start) == Update::Unreliable, "Invalid identity accepted");
    index.reset();
    index.observe(first, tuple, true, 10, FlowIndex::Time::max());
    match(index, tuple, Status::Unknown, FlowIndex::Time::max());
    bool rejected = false;
    try {
        FlowIndex invalid(0);
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    require(rejected, "Zero capacity accepted");
}
} // namespace
int main() {
    try {
        basic();
        identityAndOrdering();
        boundsAndLoss();
        std::cout
            << "PASS: flow correlation, reverse direction, collisions, PID reuse, ordering and bounds\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
