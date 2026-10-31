#include "owner_evidence.hpp"
#include <array>
#include <iostream>

using namespace skewer::traffic;
using namespace std::chrono_literals;
int main() {
    try {
        const ProcessIdentity selected{42, 100};
        const FlowIndex::Time start{};
        auto lifecycle = FlowIndex::Match{FlowIndex::Status::Observed, selected};
        std::array<std::uint32_t, 2> candidates{42, 42};
        auto check = [&](OwnerEvidence expected, auto completed, auto now, bool unknown = false) {
            if (assessOwnerEvidence(selected, lifecycle, candidates, unknown, start, completed, now, 100ms) !=
                expected) {
                throw std::runtime_error("Unexpected combined owner evidence");
            }
        };
        check(OwnerEvidence::Corroborated, start + 1ms, start + 2ms);
        check(OwnerEvidence::StaleSnapshot, start + 100ms, start + 100ms);
        check(OwnerEvidence::Unreliable, start - 1ms, start);
        check(OwnerEvidence::Unreliable, start + 1ms, start);
        check(OwnerEvidence::UnknownOwner, start, start, true);
        candidates[1] = 0;
        check(OwnerEvidence::UnknownOwner, start, start);
        candidates[1] = 99;
        check(OwnerEvidence::CompetingOwner, start, start);
        candidates[1] = 42;
        lifecycle.process->created++;
        check(OwnerEvidence::ConflictingLifecycle, start, start);
        lifecycle.process = selected;
        lifecycle.status = FlowIndex::Status::Unknown;
        check(OwnerEvidence::MissingLifecycle, start, start);
        lifecycle.status = FlowIndex::Status::Unreliable;
        check(OwnerEvidence::Unreliable, start, start);
        lifecycle.status = FlowIndex::Status::Ambiguous;
        check(OwnerEvidence::CompetingOwner, start, start);
        lifecycle.status = FlowIndex::Status::Observed;
        lifecycle.process.reset();
        check(OwnerEvidence::Unreliable, start, start);
        lifecycle.process = selected;
        if (assessOwnerEvidence(selected, lifecycle, {}, false, start, start, start, 100ms) !=
            OwnerEvidence::MissingSnapshotOwner) {
            throw std::runtime_error("Empty snapshot corroborated ownership");
        }
        std::cout << "PASS: combined lifecycle and snapshot evidence\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
