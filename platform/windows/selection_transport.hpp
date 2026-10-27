#pragma once
#include "selection_auth.hpp"

namespace skewer::windows {
// token is selected by trusted service/session setup, never supplied by IPC.
// suffix is a local identifier, not a full path. First-instance creation fails
// closed if another server already owns the name. Caller keeps this handle
// alive for the endpoint lifetime; GUI must still authenticate its server.
std::unique_ptr<Handle> createSelectionPipe(std::wstring_view suffix, HANDLE user_token);
void acceptSelection(HANDLE pipe, HANDLE cancel, DWORD timeout_ms);

// Verify a connected client pipe against a trusted, pinned server identity.
// Returns a query/synchronize-only process handle; retain it for the exchange.
std::unique_ptr<Handle> verifySelectionServer(HANDLE pipe, ProcessKey expected);
// service_name comes from installed application configuration, never the peer.
// Requires an own-process RUNNING service and rechecks SCM after pinning it.
std::unique_ptr<Handle> verifySelectionService(HANDLE pipe, const std::wstring& service_name);

// Serve one connected, message-mode server pipe opened FILE_FLAG_OVERLAPPED.
// The caller owns the pipe, its local-only ACL and connection acceptance.
// timeout_ms is a total read/write budget, not renewed by partial progress.
// On any error the caller must disconnect/close this connection, never reuse it.
// cancel is a caller-owned manual-reset event, valid for the entire call.
SelectionResult serveSelection(HANDLE pipe, HANDLE cancel, DWORD timeout_ms);
// Client pipe must already be connected and opened FILE_FLAG_OVERLAPPED.
// Authenticates the SCM server before sending, checks the retained process
// after receiving, and never reconnects. Close the pipe after the exchange.
SelectionStatus exchangeSelection(HANDLE pipe, const std::wstring& service_name, ProcessKey target,
                                  HANDLE cancel, DWORD timeout_ms);
// Read-only capability query, with the same SCM authentication and deadline.
// Caller identity is derived locally, not accepted from a GUI-supplied PID.
// ScopeUnsupported is distinct from transport failure or denied authorization.
SelectionStatus exchangeScopeProbe(HANDLE pipe, const std::wstring& service_name,
                                   skewer::traffic::RoutingScope scope, HANDLE cancel, DWORD timeout_ms);
// Wait briefly for the client to close after consuming its reply. This avoids
// discarding buffered replies on immediate DisconnectNamedPipe, without Flush.
void finishSelection(HANDLE pipe, HANDLE cancel, DWORD timeout_ms);
} // namespace skewer::windows
