#include "selection_auth.hpp"
#include <stdexcept>

namespace skewer::windows {
SelectionResult processSelectionRequest(HANDLE pipe, std::span<const std::uint8_t> request) {
    ProcessKey key{};
    const bool scope_probe = request.size() == SelectionRequest{}.size() && request[6] == 2;
    try {
        key = scope_probe ? decodeScopeProbe(request).caller : decodeSelectionRequest(request);
    } catch (const std::invalid_argument&) {
        return {encodeSelectionReply(SelectionStatus::InvalidRequest), nullptr};
    }
    try {
        auto target = authorizePipeSelection(pipe, key);
        if (scope_probe) {
            // No integrated routing backend is exposed yet. Authentication is
            // not readiness; a probe must not become a process attachment.
            return {encodeSelectionReply(SelectionStatus::ScopeUnsupported), nullptr};
        }
        return {encodeSelectionReply(SelectionStatus::Verified), std::move(target)};
    } catch (const std::runtime_error&) {
        // Do not disclose whether another user's process exists. Stale,
        // inaccessible and foreign identities have the same public outcome.
        return {encodeSelectionReply(SelectionStatus::Denied), nullptr};
    }
    // Programming errors (wrong pipe endpoint, nested impersonation) propagate
    // to the service rather than masquerading as ordinary client rejection.
}

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
