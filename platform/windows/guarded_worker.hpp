#pragma once
#include "packet_capture.hpp"
#include <exception>
#include <functional>

namespace skewer::windows {
struct GuardedWorkerResult {
    std::exception_ptr session_error;
    bool unexpected_session_exit{};
};

// The service owns capture independently of the session and GUI. A session
// failure never returns from this function before an explicit stop request.
// The session must honor its borrowed stop event and bound blocking operations.
// Cleanup runs after session join; false/exception keeps the guard armed and
// retries. The caller must retain route ownership until this function returns.
// A fatal capture failure is different: cancellation/join happens, then the
// exception propagates. WinDivert cannot protect against owner/driver failure.
GuardedWorkerResult runGuardedWorker(traffic::PacketCapture& guard, HANDLE stop,
                                     const std::function<void(HANDLE)>& session,
                                     const std::function<bool()>& cleanup);
} // namespace skewer::windows
