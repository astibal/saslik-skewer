# Windows tunnel parity contract

Linux is the behavioral reference, not just the widget layout. No Windows UI
control may claim routing protection before a privileged backend actually
enforces it. This document records the implementation boundary, not a claim that
Windows tunneling or filtering is already available.

## Existing protocol to preserve

Skewer currently obtains a paired endpoint from Saslik, derives a transport key
from the paired PSK and session context, and renews an endpoint lease. Endpoint
metadata is validated by `src/tuntom_control.hpp`. Local interface creation is
not readiness: Linux requires fresh confirmed telemetry and a successful probe
through the tunnel interface before activating routing. The privileged worker's
local lease expires without accepted control-plane heartbeats.

Tuntom V5/AUTH is a separate optional access workflow, including AUTH, RELOCATE
and CONFIG. It must not be substituted for the existing paired protocol during
the initial Windows port. A future AUTH client must additionally respect the
transport's access-data gate and apply required CONFIG items successfully.
`session_ready` alone does not establish AUTH or CONFIG success.

## Required behavior

| Event | Required result for selected applications |
| --- | --- |
| First attach/launch | Install and verify the kernel guard before admitting the application |
| Tunnel preparing | Block; an adapter existing is not evidence of a working tunnel |
| Verified session and data path | Allow only the selected tunnel path and explicit configured exemptions |
| Peer loss, stale stats, expired lease, adapter loss | Block; never fall back to the host default route |
| Transport or privileged helper crashes | Guard survives; direct egress remains blocked |
| Reconnect | Stay blocked until the replacement session and data path are verified |
| Old worker reports ready | Ignore it after session replacement or explicit Disable |
| GUI closes or crashes | Do not release application selection or remove kernel protection |
| Explicit Disable | Stop routing while retaining protection for still-selected applications |
| Explicit application Release | Deliberately return that application's future traffic to normal routing |

Unselected applications must remain unaffected. Auto mode may initially choose
a known direct lab route, as Linux does. Once a tunnel has been selected, its
loss must not silently switch back to direct mode. User-authorized mode changes
are distinct from automatic recovery.

The controller, tunnel endpoint and control plane must not be routed back into
their own tunnel. Application identity must resist PID reuse and preserve
instance boundaries. An executable-path-only firewall rule is not by itself
equivalent to selecting one running application instance.

## Windows implementation order

1. Run the existing platform-independent policy and protocol tests on Windows.
2. Port Tuntom's OS boundary: TUN packet I/O, UDP sockets, polling, randomness,
   helper invocation and process lifetime. Reuse the protocol/crypto core.
3. Use Wintun for the L3 adapter; a privileged service owns adapter, routes and
   lifetime. The unprivileged Qt GUI is only a client of authenticated local IPC.
4. Verify paired transport and data-path probes in the development VM using
   narrow test routes, without replacing the machine's default route.
5. Add per-application enforcement and diversion with a crash-surviving guard.
   Do not expose Attach until both IPv4 and IPv6 bypass behavior is tested.

Wintun supplies packet I/O, not application selection or a kill switch. WFP
dynamic-session objects are deleted when the owning session closes: a dynamic
block filter alone therefore cannot implement the required crash protection.
The concrete persistent guard/callout design and instance-level matching remain
to be implemented and tested; do not assume WinDivert alone provides them.

## Acceptance tests

`tunnel_contract_test` runs the actual shared Linux policy helpers on both OSes:
all route-mode combinations, endpoint validation, session-key vector, stale and
malformed telemetry, and reconnect eligibility/backoff. These are policy tests,
not proof of kernel enforcement.

Before Windows routing is enabled, packet-level integration tests must capture
the physical egress and verify no direct leak during tunnel loss, helper kill,
GUI restart, adapter deletion, lease expiry and reconnect. Exercise TCP, UDP,
IPv4, IPv6, existing sockets, spawned children and PID reuse. Include DNS through
the system resolver; shared resolver traffic must not become an unnoticed bypass.
Also verify another unselected application retains normal connectivity and an
explicit Release affects only the intended instance. Reboot persistence requires
its own test if protection is advertised across reboot.

## References

- Tuntom: `docs/PROTOCOL_V5.md`, `src/tun_device.hpp`, `src/udp_endpoint.hpp`.
- Linux: `src/tuntom_process.cpp`, `src/tuntom_routing.hpp`, `src/net_helper.cpp`,
  `src/routing_guard.hpp`, `tests/routing_guard_packet_test.py`.
- [Wintun API](https://git.zx2c4.com/wintun/about/)
- [WFP object lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/best-practices)
