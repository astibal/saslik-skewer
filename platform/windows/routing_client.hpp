#pragma once
#include "routing_control.hpp"

namespace skewer::windows {
// Connect only to a local, installed service's fixed pipe namespace. No request
// is retried after writing; callers must reconcile uncertain results via Status.
std::unique_ptr<Handle> connectRoutingService(const std::wstring& service_name, bool pairing, HANDLE cancel,
                                              DWORD timeout_ms);
} // namespace skewer::windows
