#pragma once

#include <windows.h>
#include <string>

namespace skewer::windows::traffic {

// A transport-independent, block-only WFP primitive. Its selection scope is
// ALL instances/users of one executable path, NOT one PID or process tree.
// The caller owns a stable, unique policy ID and must persist it for recovery.
// This is not yet the instance-level interception backend exposed by the GUI.
class AppImageBlock final {
public:
    AppImageBlock(GUID policy_id, std::wstring executable);
    void arm() const;
    bool installed() const;
    void release() const;
    // Destruction deliberately does not release persistent kernel protection.

private:
    enum class Operation { Inspect, Arm, Release };
    bool perform(Operation operation) const;
    GUID id_;
    std::wstring executable_;
};

} // namespace skewer::windows::traffic
