#include "pending_packets.hpp"
#include <array>
#include <iostream>

namespace {
using Queue = skewer::traffic::PendingPackets<std::uint64_t>;
using namespace std::chrono_literals;
const Queue::Time start{};
const std::array<std::uint8_t, 3> payload{1, 2, 3};
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
void limitsAndOwnership() {
    Queue queue(2, 22, 100ms);
    auto input = payload;
    const auto first = queue.hold(input, 42, start);
    const auto second = queue.hold(payload, 43, start);
    require(first && second && queue.bytes() == 22, "Exact capacity rejected");
    input[0] = 99;
    require(!queue.hold(payload, 44, start), "Full buffer accepted packet");
    const auto packet = queue.take(*first, start + 1ms);
    require(packet && packet->bytes[0] == 1 && packet->context == 42, "Capture was not owned");
    require(!queue.take(*first, start + 1ms), "Ticket consumed twice");
    require(queue.discard(*second) && queue.bytes() == 0, "Discard accounting");
    const auto replacement = queue.hold(payload, 45, start + 1ms);
    require(replacement && *replacement > *second && !queue.take(*second, start + 1ms), "Ticket reused");
    Queue byteLimited(10, 12, 100ms);
    require(byteLimited.hold(payload, 0, start).has_value(), "Small buffer rejected first packet");
    require(!byteLimited.hold(payload, 0, start), "Byte budget exceeded");
    require(!byteLimited.hold({}, 0, start), "Empty packet accepted");
    const std::array<std::uint8_t, 5> oversized{};
    require(!byteLimited.hold(oversized, 0, start), "Oversized packet accepted");
    Queue countLimited(1, 1000, 100ms);
    require(countLimited.hold(payload, 0, start).has_value(), "First count slot");
    require(!countLimited.hold(payload, 0, start), "Count budget exceeded");
}
void expiryAndStop() {
    Queue queue(4, 1000, 100ms);
    const auto first = queue.hold(payload, 0, start);
    const auto second = queue.hold(payload, 1, start + 50ms);
    require(queue.expire(start + 99ms) == 0, "Premature expiry");
    require(!queue.take(*first, start + 100ms), "Deadline allowed release");
    require(queue.size() == 1 && queue.bytes() == 11, "Expiry accounting");
    require(queue.take(*second, start + 149ms).has_value(), "Live packet lost");
    bool backwards{};
    try {
        queue.expire(start);
    } catch (const std::invalid_argument&) {
        backwards = true;
    }
    require(backwards, "Backward clock accepted");
    const auto held = queue.hold(payload, 2, start + 150ms);
    queue.stop();
    require(!queue.take(*held, start + 150ms) && queue.bytes() == 0, "Stop released pending work");
    require(!queue.hold(payload, 0, start + 150ms), "Stopped queue revived");
    Queue saturating(2, 1000, 100ms);
    const auto end = saturating.hold(payload, 0, Queue::Time::max() - 1ms);
    require(end && !saturating.take(*end, Queue::Time::max()), "Deadline overflow");
    Queue replenished(1, 11, 1ms);
    require(replenished.hold(payload, 0, start).has_value(), "Initial limited packet");
    require(replenished.hold(payload, 0, start + 1ms).has_value(), "Expired packet occupied capacity");
}
} // namespace
int main() {
    try {
        limitsAndOwnership();
        expiryAndStop();
        std::cout << "PASS: bounded pending packet ownership, limits, expiry and shutdown\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
