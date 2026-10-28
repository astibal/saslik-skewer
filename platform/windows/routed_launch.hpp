#pragma once
#include "routing_client.hpp"

namespace skewer::windows {
struct RoutedLaunch {
    // Caller owns both handles. Closing them does not stop the process/service.
    PROCESS_INFORMATION process{};
    ProcessKey identity{};
    std::uint64_t generation{};
};

// Caller-user launch, never SYSTEM launch or shell execution. The new process
// remains suspended until its authenticated service generation is Active.
// Failure terminates only this newly created child, never a discovered process.
// Currently one process / fresh IPv4 TCP, not descendants or existing instances.
RoutedLaunch launchRouted(const std::wstring& service, const std::wstring& executable,
                          const std::vector<std::wstring>& arguments, HANDLE cancel,
                          const EnvironmentOverrides& environment = {},
                          DWORD timeout_ms = 30000);
} // namespace skewer::windows
