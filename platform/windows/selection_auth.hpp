#pragma once
#include "processes.hpp"
#include "selection_request.hpp"
#include <memory>

namespace skewer::windows {
// Call only after reading the request from this connected server-side pipe.
// Server creation must reject remote clients and apply an explicit local ACL.
// SID/identity is taken from the OS pipe token, never request-supplied identity.
// The result pins the verified target process but does not change its routing.
std::unique_ptr<ProcessTarget> authorizePipeSelection(HANDLE pipe, ProcessKey requested);

struct SelectionResult {
    SelectionReply reply;
    std::unique_ptr<ProcessTarget> target;
};

// One already-read complete request. Keep the pinned target; never reopen the
// PID under the service account. This does not change packet policy. Transport
// framing, timeouts and client/server authentication remain the caller's job.
SelectionResult processSelectionRequest(HANDLE pipe, std::span<const std::uint8_t> request);
} // namespace skewer::windows
