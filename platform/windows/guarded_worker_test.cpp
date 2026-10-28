#include "guarded_worker.hpp"
#include <atomic>
#include <future>
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}
void exercise(const std::wstring& dll, bool failure, bool early_return, bool pre_cancelled) {
    // Real signed WinDivert handle, but a fixed false filter: no traffic changes.
    traffic::PacketCapture capture(dll, "false");
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(stop), "Create test cancellation");
    if (pre_cancelled) {
        SetEvent(stop.get());
    }
    std::atomic_uint starts{}, cleanups{};
    std::atomic_bool session_done{}, allow_cleanup{};
    auto work = std::async(std::launch::async, [&] {
        return runGuardedWorker(
            capture, stop.get(),
            [&](HANDLE cancel) {
                ++starts;
                if (failure) {
                    session_done = true;
                    throw std::runtime_error("Simulated tunnel failure");
                }
                if (!early_return) {
                    require(WaitForSingleObject(cancel, 5000) == WAIT_OBJECT_0, "Session not cancelled");
                }
                session_done = true;
            },
            [&] {
                require(pre_cancelled || session_done, "Cleanup raced with running session");
                ++cleanups;
                if (cleanups == 1) {
                    throw std::runtime_error("Simulated cleanup failure");
                }
                return allow_cleanup.load();
            });
    });
    struct Finish {
        HANDLE stop;
        std::atomic_bool& allow;
        ~Finish() {
            allow = true;
            SetEvent(stop);
        }
    } finish{stop.get(), allow_cleanup};
    require(work.wait_for(std::chrono::milliseconds(700)) == std::future_status::timeout,
            "Session failure or return released the egress guard");
    SetEvent(stop.get());
    require(work.wait_for(std::chrono::milliseconds(400)) == std::future_status::timeout,
            "Unfinished cleanup released the egress guard");
    allow_cleanup = true;
    require(work.wait_for(std::chrono::seconds(3)) == std::future_status::ready, "Clean shutdown stalled");
    const auto result = work.get();
    require(bool(result.session_error) == failure, "Session error was lost");
    require(result.unexpected_session_exit == (failure || early_return), "Unexpected exit was not reported");
    require(starts == (pre_cancelled ? 0U : 1U) && cleanups >= 2, "Incorrect session/cleanup lifetime");
    require(capture.stats().captured_packets == 0 && capture.stats().injected_packets == 0,
            "False-filter fixture touched traffic");
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 3 || std::wstring(argv[1]) != L"--live") {
            throw std::invalid_argument("Expected --live TRUSTED_WINDIVERT_DLL in elevated VM");
        }
        exercise(argv[2], true, false, false);
        exercise(argv[2], false, true, false);
        exercise(argv[2], false, false, false);
        exercise(argv[2], false, false, true);
        std::cout << "PASS: tunnel failure and return preserve guard; stop joins and waits for cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
