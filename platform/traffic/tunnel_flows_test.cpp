#include "tunnel_flows.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace skewer::traffic;
using namespace std::chrono_literals;
namespace {
void check(bool yes, const char* message) {
    if (!yes) {
        throw std::runtime_error(message);
    }
}
std::vector<std::uint8_t> request() {
    std::vector<std::uint8_t> p(28);
    p[0] = 0x45;
    p[3] = 28;
    p[8] = 64;
    p[9] = 17;
    p[12] = 192;
    p[13] = 168;
    p[14] = 1;
    p[15] = 2;
    p[16] = 1;
    p[17] = 1;
    p[18] = 1;
    p[19] = 1;
    p[20] = 0xc3;
    p[21] = 0x50;
    p[23] = 53;
    p[25] = 8;
    return p;
}
std::vector<std::uint8_t> reply(std::vector<std::uint8_t> p) {
    for (unsigned i = 0; i < 4; ++i) {
        std::swap(p[12 + i], p[16 + i]);
    }
    std::swap(p[20], p[22]);
    std::swap(p[21], p[23]);
    return p;
}
} // namespace
int main() {
    try {
        const FlowIdentity a{{42, 100}, 1}, b{{42, 101}, 2};
        const TunnelFlows::Time now{};
        TunnelFlows table({10, 253, 0, 10}, 2, 10s);
        auto one = request(), two = request();
        const auto original = *parsePacketTuple(one).tuple;
        check(table.outbound(a, one, now), "First mapping failed");
        check(table.outbound(b, two, now), "Second mapping failed");
        check(parsePacketTuple(one).tuple->source_port != parsePacketTuple(two).tuple->source_port,
              "Port collision");
        auto response = reply(one);
        check(table.inbound(response, now) == a, "Wrong reverse owner");
        check(*parsePacketTuple(response).tuple == original.reversed(), "Wrong reverse translation");
        auto forged = reply(one);
        forged[12] = 8;
        const auto saved = forged;
        check(!table.inbound(forged, now) && forged == saved, "Wrong remote accepted");
        auto extra = request();
        check(!table.outbound({{43, 100}, 3}, extra, now) && extra == request(), "Capacity not enforced");
        table.release(a);
        response = reply(one);
        check(!table.inbound(response, now), "Released mapping revived");
        extra = request();
        check(table.outbound(a, extra, now), "Replacement mapping failed");
        check(parsePacketTuple(extra).tuple->source_port != parsePacketTuple(one).tuple->source_port,
              "Retired port reused");
        table.expire(now + 10s);
        check(table.size() == 0, "Idle mappings retained");
        response = reply(two);
        check(!table.inbound(response, now + 10s), "Expired mapping revived");
        TunnelFlows multi({10, 253, 0, 10});
        auto peerOne = request(), peerTwo = request();
        peerTwo[16] = 8;
        check(multi.outbound(a, peerOne, now) && multi.outbound(a, peerTwo, now),
              "Multi-peer UDP socket rejected");
        check(parsePacketTuple(peerOne).tuple->source_port != parsePacketTuple(peerTwo).tuple->source_port,
              "Multi-peer mappings collide");
        auto peerReply = reply(peerTwo);
        check(multi.inbound(peerReply, now) == a && peerReply[12] == 8, "Multi-peer return failed");
        multi.release(a);
        check(multi.size() == 0, "Socket release left peer mappings");
        TunnelFlows exhausted({10, 253, 0, 10}, 2, 10s, 65535);
        extra = request();
        check(exhausted.outbound(a, extra, now), "Last port unavailable");
        exhausted.release(a);
        extra = request();
        check(!exhausted.outbound(b, extra, now), "Exhaustion wrapped ports");
        TunnelFlows stopped({10, 253, 0, 10});
        extra = request();
        check(stopped.outbound(a, extra, now + 1s), "Setup failed");
        response = reply(extra);
        check(!stopped.inbound(response, now), "Backwards clock accepted");
        extra = request();
        check(!stopped.outbound(a, extra, now + 2s), "Stopped epoch revived");
        std::cout << "PASS: tunnel flow collision, reverse path and lifetime\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
