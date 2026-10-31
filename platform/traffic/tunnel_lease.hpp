#pragma once
#include <chrono>
#include <stdexcept>

namespace skewer::traffic {
// One owner, monotonic time. A late response never revives an expired lease.
// Count TTL from request start, not receipt, to avoid granting network latency.
class TunnelLease final {
public:
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;
    TunnelLease(Time started, Time completed, std::chrono::seconds ttl)
        : deadline_(started + ttl), observed_(completed), ttl_(ttl) {
        if (ttl.count() < 10 || ttl.count() > 3600 || completed < started || completed >= deadline_) {
            throw std::invalid_argument("Invalid or expired tunnel lease");
        }
    }
    bool valid(Time now) {
        if (now < observed_ || now >= deadline_) {
            stopped_ = true;
        }
        observed_ = now;
        return !stopped_;
    }
    bool renew(Time started, Time completed) {
        if (!valid(completed) || started > completed || completed >= started + ttl_) {
            stopped_ = true;
            return false;
        }
        // Renewal is never allowed to shorten the currently granted lease.
        if (started + ttl_ < deadline_) {
            stopped_ = true;
            return false;
        }
        deadline_ = started + ttl_;
        return true;
    }
    void stop() { stopped_ = true; }

private:
    Time deadline_, observed_;
    std::chrono::seconds ttl_;
    bool stopped_{};
};
} // namespace skewer::traffic
