#include "selection_registry.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace skewer::windows {
SelectionRegistry::SelectionRegistry(std::size_t limit) : limit_(limit) {
    if (!limit || limit > 65536) {
        throw std::invalid_argument("Invalid selection registry capacity");
    }
}

SelectionRegistry::Entry SelectionRegistry::retain(std::unique_ptr<ProcessTarget> target) {
    if (!target) {
        throw std::invalid_argument("Selection requires an authorized target");
    }
    if (!target->running()) {
        throw std::runtime_error("Selected process has exited");
    }
    const auto key = target->key();
    for (const auto& item : targets_) {
        if (item.entry.process == key) {
            // Retrying an operation does not rotate its packet-work generation.
            return item.entry;
        }
    }
    // Explicit reap is deliberate: retiring membership may require the caller
    // to retire packet queues and policy first. Never hide that inside retain.
    if (targets_.size() >= limit_) {
        throw std::length_error("Selection registry is full");
    }
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("Selection generation exhausted");
    }
    const Entry entry{key, ++generation_};
    targets_.push_back({entry, std::move(target)});
    return entry;
}

bool SelectionRegistry::release(Entry expected) {
    const auto found = std::find_if(targets_.begin(), targets_.end(),
                                    [&](const Owned& item) { return item.entry == expected; });
    if (found == targets_.end()) {
        return false;
    }
    // Only drop our query handle. Releasing or destroying this registry never
    // terminates an application, and does not itself remove network policy.
    targets_.erase(found);
    return true;
}

bool SelectionRegistry::current(Entry expected) const {
    const auto found = std::find_if(targets_.begin(), targets_.end(),
                                    [&](const Owned& item) { return item.entry == expected; });
    return found != targets_.end() && found->target->running();
}

std::vector<SelectionRegistry::Entry> SelectionRegistry::snapshot() const {
    std::vector<Entry> result;
    result.reserve(targets_.size());
    for (const auto& item : targets_) {
        if (item.target->running()) {
            result.push_back(item.entry);
        }
    }
    return result;
}

std::size_t SelectionRegistry::reap() {
    return std::erase_if(targets_, [](const Owned& item) { return !item.target->running(); });
}
} // namespace skewer::windows
