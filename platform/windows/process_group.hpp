#pragma once

#include "processes.hpp"
#include <memory>

namespace skewer::windows {

// Pins a selected process tree in a Windows Job Object. The group deliberately
// has no kill-on-close limit: routing ownership and application lifetime are
// independent, and closing Skewer must never terminate user applications.
class ProcessGroup final {
public:
    ProcessGroup(const ProcessTarget& root, const ServiceOwner& owner);
    ProcessGroup(const ProcessGroup&) = delete;
    ProcessGroup& operator=(const ProcessGroup&) = delete;

    const ProcessKey& root() const { return root_; }
    bool contains(DWORD pid) const;

    // Returns one newly observed, owner-validated process. Notifications are
    // advisory; callers must still use the retained ProcessTarget identity.
    std::unique_ptr<ProcessTarget> next(DWORD timeout_ms = 0);

private:
    ServiceOwner owner_;
    ProcessKey root_;
    Handle job_;
    Handle completion_;
};

} // namespace skewer::windows
