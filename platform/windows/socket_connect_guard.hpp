#pragma once
#include "processes.hpp"
#include <memory>

namespace skewer::windows::traffic {
// Fresh socket attempts only, not established sockets or descendants. The caller
// retains the authenticated process for this entire lifetime and retires the
// guard on process exit. Closing the handle intentionally releases this policy;
// WinDivert owner/driver failure has the same documented lab limitation.
class SocketConnectGuard final {
public:
    enum class Mode { All, UnsupportedForIpv4Tcp };
    SocketConnectGuard(const std::wstring& dll, const ProcessTarget& target, Mode mode);
    ~SocketConnectGuard();
    SocketConnectGuard(const SocketConnectGuard&) = delete;
    SocketConnectGuard& operator=(const SocketConnectGuard&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace skewer::windows::traffic
