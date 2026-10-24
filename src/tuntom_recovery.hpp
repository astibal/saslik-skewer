#pragma once
#include <QStringList>

namespace Tuntom {
inline QStringList controllerArguments(const QString& executable, const QString& endpoint) {
    // The control plane must not inherit the routed cgroup from a Skewer shell.
    // A transient user service gives it an independent cgroup and forwards only
    // private pipes. EOF still tells the controller to release its tunnel.
    return {"--user", "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec",
        "--slice=app.slice", "--property=KillMode=control-group", "--property=TimeoutStopSec=10",
        "--", executable, "tunnel", endpoint, "--gui-route"};
}

// Recovery may reuse authorization, but must never create it in the background.
// Selection remains pinned to the tunnel while the kernel guard stays closed.
class Recovery {
public:
    static bool allowed(bool requested, bool selected, bool connectedIntent,
                        bool quitting, bool clientRunning) {
        return requested && selected && connectedIntent && !quitting && !clientRunning;
    }
    int nextDelayMs() {
        const int delay = delay_ms_;
        delay_ms_ = delay_ms_ < 15000 ? delay_ms_ * 2 : 30000;
        return delay;
    }
    void reset() { delay_ms_ = 5000; }
private:
    int delay_ms_ = 5000;
};
}
