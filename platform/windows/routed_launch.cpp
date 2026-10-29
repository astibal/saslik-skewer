#include "routed_launch.hpp"
#include <algorithm>

namespace skewer::windows {
namespace {
class PendingChild final {
public:
    explicit PendingChild(PROCESS_INFORMATION process) : process_(process) {}
    PendingChild(const PendingChild&) = delete;
    PendingChild& operator=(const PendingChild&) = delete;
    ~PendingChild() {
        if (!released_) {
            // Still suspended on every failure path. Never resume merely to
            // clean up, and never terminate by a potentially recycled PID.
            TerminateProcess(process_.hProcess, ERROR_CANCELLED);
            WaitForSingleObject(process_.hProcess, 2000);
            CloseHandle(process_.hThread);
            CloseHandle(process_.hProcess);
        }
    }
    const PROCESS_INFORMATION& process() const { return process_; }
    PROCESS_INFORMATION resume() {
        if (ResumeThread(process_.hThread) != 1) {
            throw std::runtime_error("Cannot resume routed process");
        }
        released_ = true;
        return process_;
    }

private:
    PROCESS_INFORMATION process_;
    bool released_{};
};
} // namespace

RoutedLaunch launchRouted(const std::wstring& service, const std::wstring& executable,
                          const std::vector<std::wstring>& arguments, HANDLE cancel,
                          const EnvironmentOverrides& environment, DWORD timeout_ms, LaunchConsole console) {
    if (!timeout_ms || timeout_ms > 120000) {
        throw std::invalid_argument("Routed launch timeout must be 1..120000 ms");
    }
    const auto deadline = GetTickCount64() + timeout_ms;
    const auto remaining = [&]() -> DWORD {
        if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT) {
            throw std::runtime_error("Routed launch cancelled or invalid cancellation event");
        }
        const auto now = GetTickCount64();
        if (now >= deadline) {
            throw std::runtime_error("Routed launch timed out before readiness");
        }
        return static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, 2000));
    };
    const auto command = [&](RoutingCommand operation, std::uint64_t generation) {
        auto pipe = connectRoutingService(service, false, cancel, remaining());
        return exchangeRoutingCommand(pipe->get(), service, operation, generation, cancel, remaining());
    };
    const auto initial = command(RoutingCommand::Status, 0);
    if (initial.result != RoutingResult::Ok ||
        (initial.phase != RoutingPhase::Idle && initial.phase != RoutingPhase::Failed)) {
        throw std::runtime_error("Routing service is busy; process was not launched");
    }
    PendingChild child(launch(executable, arguments, LaunchMode::Suspended, environment, console));
    const auto identity = processKey(child.process().hProcess, child.process().dwProcessId);
    auto pipe = connectRoutingService(service, false, cancel, remaining());
    // Never retry Start: loss of its reply may mean it was already accepted.
    // On uncertainty the child stays suspended and is terminated by its handle.
    const auto started =
        exchangeSelectedRouting(pipe->get(), service, identity, initial.generation, cancel, remaining());
    pipe.reset();
    if (started.result != RoutingResult::Ok) {
        throw std::runtime_error("Selected routing start rejected; process was not resumed");
    }
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        if (state.result != RoutingResult::Ok || state.generation != started.generation ||
            (state.phase != RoutingPhase::Starting && state.phase != RoutingPhase::Active &&
             state.phase != RoutingPhase::Blocked)) {
            throw std::runtime_error("Selected routing stopped before process readiness");
        }
        if (state.phase == RoutingPhase::Active) {
            remaining(); // Cancellation wins over a simultaneous Active reply.
            return {child.resume(), identity, started.generation};
        }
        const auto delay = std::min<DWORD>(remaining(), 50);
        if (WaitForSingleObject(cancel, delay) != WAIT_TIMEOUT) {
            throw std::runtime_error("Routed launch cancelled before process readiness");
        }
    }
}
} // namespace skewer::windows
