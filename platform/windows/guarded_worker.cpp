#include "guarded_worker.hpp"
#include <future>
#include <stdexcept>

namespace skewer::windows {
namespace {
bool signalled(HANDLE event) {
    const auto state = WaitForSingleObject(event, 0);
    if (state != WAIT_OBJECT_0 && state != WAIT_TIMEOUT) {
        throw std::runtime_error("Cannot inspect guarded worker cancellation");
    }
    return state == WAIT_OBJECT_0;
}
} // namespace

GuardedWorkerResult runGuardedWorker(traffic::PacketCapture& guard, HANDLE stop,
                                     const std::function<void(HANDLE)>& session,
                                     const std::function<bool()>& cleanup) {
    if (!session || !cleanup) {
        throw std::invalid_argument("Guarded worker requires session and cleanup");
    }
    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    // Never signal this event: continue draining/discarding while a stopped
    // session unwinds or route cleanup needs another attempt.
    Handle capture_wait(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!cancel || !capture_wait) {
        throw std::runtime_error("Cannot create guarded worker events");
    }
    const bool initially_stopped = signalled(stop);
    if (initially_stopped) {
        SetEvent(cancel.get());
    }
    auto work = std::async(std::launch::async, [&] {
        if (!initially_stopped) {
            session(cancel.get());
        }
    });
    // Destroy before the future so exceptional paths cancel before joining.
    struct CancelOnExit {
        HANDLE event;
        ~CancelOnExit() { SetEvent(event); }
    } cancel_on_exit{cancel.get()};
    GuardedWorkerResult result;
    bool joined = false;
    bool clean = false;
    ULONGLONG next_cleanup = 0;
    for (;;) {
        const bool stopping = signalled(stop);
        if (stopping && !SetEvent(cancel.get())) {
            throw std::runtime_error("Cannot cancel guarded session");
        }
        if (!joined && work.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            try {
                work.get();
            } catch (...) {
                result.session_error = std::current_exception();
            }
            joined = true;
            result.unexpected_session_exit = !stopping;
        }
        if (joined && !clean && GetTickCount64() >= next_cleanup) {
            try {
                clean = cleanup();
            } catch (...) {
                // A failed cleanup is not permission to drop the guard.
            }
            next_cleanup = GetTickCount64() + 250;
        }
        if (stopping && joined && clean) {
            return result;
        }
        const auto captured = guard.next(capture_wait.get(), 100);
        if (captured.status == traffic::PacketCapture::Status::Cancelled) {
            throw std::runtime_error("Egress guard unexpectedly cancelled");
        }
        // This is exclusively the physical-egress deny path. Never reinject.
    }
}
} // namespace skewer::windows
