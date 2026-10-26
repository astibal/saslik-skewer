#pragma once

#include "processes.hpp"
#include <memory>
#include <optional>

namespace skewer::windows::traffic {

struct FlowEndpoint {
    // Canonical text from WinDivert's formatter (IPv4 dotted or IPv6 notation).
    std::string address;
    std::uint16_t port{}; // Host byte order.
};

struct FlowEvent {
    enum class Kind { Established, Deleted };
    Kind kind{};
    ProcessKey process;
    std::uint64_t endpoint_id{}, parent_endpoint_id{};
    std::int64_t timestamp_ticks{}; // QueryPerformanceCounter time base.
    std::uint8_t protocol{};        // IPPROTO_TCP or IPPROTO_UDP.
    bool ipv6{}, outbound{}, loopback{};
    FlowEndpoint local, remote;
};

// Passive connection metadata only: no packets, policy changes or reinjection.
// One consumer owns reads/destruction; cancel and join it before destruction.
// The driver may drop events under load, so this is not a security authority.
class FlowObserver final {
public:
    enum class Status { Event, Timeout, Cancelled, TargetExited };
    struct Result {
        Status status;
        std::optional<FlowEvent> event; // Present only for Status::Event.
    };

    // Load only from an absolute, trusted local installation directory. The
    // official driver beside the DLL may be installed on first open (admin).
    FlowObserver(const std::wstring& dll_path, ProcessKey target);
    // Service path: consume the authenticated IPC selection without reopening
    // its PID or comparing its owner against the service's own account.
    FlowObserver(const std::wstring& dll_path, std::unique_ptr<ProcessTarget> target);
    bool targetRunning() const;
    ~FlowObserver();
    FlowObserver(const FlowObserver&) = delete;
    FlowObserver& operator=(const FlowObserver&) = delete;

    // Cancellation and process exit take priority over queued events. Both are
    // terminal; a timeout retains the pending read for the next call.
    Result next(HANDLE cancellation, DWORD timeout_ms);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace skewer::windows::traffic
