#pragma once
#include "processes.hpp"
#include <memory>

namespace skewer::windows {
// Call only after reading the request from this connected server-side pipe.
// Server creation must reject remote clients and apply an explicit local ACL.
// SID/identity is taken from the OS pipe token, never request-supplied identity.
// The result pins the verified target process but does not change its routing.
std::unique_ptr<ProcessTarget> authorizePipeSelection(HANDLE pipe, ProcessKey requested);
} // namespace skewer::windows
