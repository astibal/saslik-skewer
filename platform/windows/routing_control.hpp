#pragma once
#include "selection_transport.hpp"
#include <atomic>
#include <functional>
#include <future>

namespace skewer::windows {
enum class RoutingCommand : std::uint8_t { Status, Start, Stop };
enum class RoutingPhase : std::uint8_t { Idle, Starting, Active, Blocked, Stopping, Failed };
enum class RoutingResult : std::uint8_t { Ok, Stale, Busy };
struct RoutingReply {
    RoutingResult result{};
    RoutingPhase phase{};
    std::uint64_t generation{};
};
struct RoutingSignals {
    std::atomic_bool ready{};
    std::atomic_bool blocked{};
};

// One service command thread owns this controller. The runner owns all runtime
// resources, must honor stop and must not return until protected cleanup ends.
// IPC disconnect does not call stop. No global lock or GUI lifetime dependency.
class RoutingController final {
public:
    using Runner = std::function<void(HANDLE, RoutingSignals&)>;
    explicit RoutingController(Runner runner);
    ~RoutingController();
    RoutingReply command(RoutingCommand command, std::uint64_t generation);

private:
    void reap();
    Runner runner_;
    Handle stop_;
    RoutingSignals signals_;
    std::future<void> work_;
    std::uint64_t generation_{};
    bool stopping_{};
    RoutingPhase terminal_{RoutingPhase::Idle};
};

using RoutingHandler = std::function<RoutingReply(RoutingCommand, std::uint64_t)>;
// Dedicated connection; actual caller PID/birth and trusted owner token are
// checked before invoking the handler. Status is authenticated too.
void serveRoutingCommand(HANDLE pipe, HANDLE owner_token, HANDLE cancel, DWORD timeout_ms,
                         const RoutingHandler& handler);
void serveRoutingCommand(HANDLE pipe, const ServiceOwner& owner, HANDLE cancel, DWORD timeout_ms,
                         const RoutingHandler& handler);
RoutingReply exchangeRoutingCommand(HANDLE pipe, const std::wstring& service_name, RoutingCommand command,
                                    std::uint64_t generation, HANDLE cancel, DWORD timeout_ms);
} // namespace skewer::windows
