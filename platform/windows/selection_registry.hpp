#pragma once
#include "processes.hpp"
#include <memory>
#include <vector>

namespace skewer::windows {
// Desired selection owned by one service/session worker, not a pipe connection.
// This is bookkeeping, NOT evidence that interception or routing is installed.
// Every target must already be authorized against that worker's user token.
// Single-worker access only: packet workers receive snapshots, never pointers.
class SelectionRegistry final {
public:
    struct Entry {
        ProcessKey process;
        std::uint64_t generation;
        bool operator==(const Entry&) const = default;
    };
    explicit SelectionRegistry(std::size_t limit = 1024);
    Entry retain(std::unique_ptr<ProcessTarget> target);
    bool release(Entry expected);
    bool current(Entry expected) const;
    std::vector<Entry> snapshot() const;
    std::size_t reap();

private:
    struct Owned {
        Entry entry;
        std::unique_ptr<ProcessTarget> target;
    };
    const std::size_t limit_;
    std::uint64_t generation_{};
    std::vector<Owned> targets_;
};
} // namespace skewer::windows
