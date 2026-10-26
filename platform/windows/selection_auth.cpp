#include "selection_auth.hpp"
#include <stdexcept>

namespace skewer::windows {
std::unique_ptr<ProcessTarget> authorizePipeSelection(HANDLE pipe, ProcessKey requested) {
    DWORD flags{};
    if (!GetNamedPipeInfo(pipe, &flags, nullptr, nullptr, nullptr) || !(flags & PIPE_SERVER_END)) {
        throw std::invalid_argument("Selection requires a connected server-side pipe");
    }
    HANDLE previous{};
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &previous)) {
        CloseHandle(previous);
        throw std::logic_error("Selection authorization requires a non-impersonating worker");
    }
    if (GetLastError() != ERROR_NO_TOKEN) {
        throw std::runtime_error("Cannot verify worker impersonation state");
    }
    if (!ImpersonateNamedPipeClient(pipe)) {
        throw std::runtime_error("Cannot authenticate pipe client");
    }
    // No allocations, exceptions or process queries before reverting. Retain
    // only TOKEN_QUERY access; this token cannot launch or impersonate a user.
    HANDLE raw{};
    const bool opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw) != FALSE;
    if (!RevertToSelf()) {
        // Continuing with an unknown security context is unsafe. Terminate the
        // service rather than execute another request under the client's token.
        std::terminate();
    }
    Handle client(raw);
    if (!opened) {
        throw std::runtime_error("Cannot query authenticated pipe token");
    }
    return std::make_unique<ProcessTarget>(requested, client.get());
}
} // namespace skewer::windows
