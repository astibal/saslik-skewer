#pragma once
#include "selection_transport.hpp"
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>

namespace skewer::windows {
enum class RoutingCommand : std::uint8_t { Status, Start, Stop };
enum class RoutingPhase : std::uint8_t { Idle, Starting, Active, Blocked, Stopping, Failed };
enum class RoutingResult : std::uint8_t { Ok, Stale, Busy };
enum class RoutingScope : std::uint8_t { None, WholeHost, SelectedProcess };
enum class RoutingTransport : std::uint8_t { None, Tunnel, Direct };
struct RoutingReply {
    RoutingResult result{};
    RoutingPhase phase{};
    std::uint64_t generation{};
    RoutingScope scope{};
    RoutingTransport transport{};
    std::optional<ProcessKey> selected;
    std::string detail;
    bool paired{};
};
enum class RoutingStage : std::uint8_t { None, Preparing, Connecting, Intercepting, StartingSession };
struct RoutingSignals {
    std::atomic_bool ready{};
    std::atomic_bool blocked{};
    std::atomic<RoutingStage> stage{RoutingStage::None};
    std::atomic<std::shared_ptr<const std::string>> retry_error{};
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
    std::future<std::string> work_;
    std::uint64_t generation_{};
    bool stopping_{};
    RoutingPhase terminal_{RoutingPhase::Idle};
    std::string detail_;
};

using RoutingHandler = std::function<RoutingReply(RoutingCommand, std::uint64_t)>;
using SelectedRoutingHandler =
    std::function<RoutingReply(std::unique_ptr<ProcessTarget>, std::uint64_t)>;
using DirectRoutingHandler =
    std::function<RoutingReply(std::array<std::uint8_t, 4>, std::uint64_t)>;
// Dedicated connection; actual caller PID/birth and trusted owner token are
// checked before invoking the handler. Status is authenticated too.
void serveRoutingCommand(HANDLE pipe, HANDLE owner_token, HANDLE cancel, DWORD timeout_ms,
                         const RoutingHandler& handler);
void serveRoutingCommand(HANDLE pipe, const ServiceOwner& owner, HANDLE cancel, DWORD timeout_ms,
                         const RoutingHandler& handler, const SelectedRoutingHandler& selected = {},
                         const DirectRoutingHandler& direct = {});
RoutingReply exchangeRoutingCommand(HANDLE pipe, const std::wstring& service_name, RoutingCommand command,
                                    std::uint64_t generation, HANDLE cancel, DWORD timeout_ms);
// Separate operation: never reinterpret a selected start as whole-host Start.
RoutingReply exchangeSelectedRouting(HANDLE pipe, const std::wstring& service_name, ProcessKey target,
                                    std::uint64_t generation, HANDLE cancel, DWORD timeout_ms);
RoutingReply exchangeDirectRouting(HANDLE pipe, const std::wstring& service_name,
                                   std::array<std::uint8_t, 4> gateway, std::uint64_t generation,
                                   HANDLE cancel, DWORD timeout_ms);
} // namespace skewer::windows
