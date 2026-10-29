# Windows tunnel parity contract

Linux is the behavioral reference, not just the widget layout. No Windows UI
control may claim routing protection before a privileged backend actually
enforces it. This document records the implementation boundary. Windows
whole-host IPv4 through either Tuntom or a directly reachable on-link gateway,
and selected-process IPv4 TCP/UDP routing through Tuntom, are available; the
limits below remain part of the contract.

## Multiple application trees (GUI, service and CLI)

An active selected-process session accepts up to 64 independent application
trees without replacing its tunnel generation. Use `skewer-routing-control add
SERVICE GENERATION PID BIRTH` and `remove` with the same arguments. `status`
reports the authoritative `selections` array; `selected` remains the first root
for older consumers. The GUI launcher, Shell and Attach actions can add another
tree to the active session. Every selected root receives a routing badge.
Release targets the selected root row; with only one tree it can also release
that sole selection without requiring a row selection.

Add revalidates the configured owner and process creation time. Remove accepts
an exact previously selected root, including an exited root with live children.
It retires that tree's packet queues, reverse mappings and guards without killing
applications or stopping other selections. The final removal retires routing.
Overlapping trees are rejected rather than giving Release ambiguous semantics.

Extended status and mutation replies use protocol version 7. Legacy operations
retain their version-6 response format. New clients require an upgraded service.
Mutation requests are not automatically retried after IPC loss: inspect status
because a request may already have been applied. The disposable-service fixture
tests concurrent HTTPS, independent Release, fresh HTTPS from the remaining tree,
unchanged generation and rejection of stale-generation mutations. The desktop
fixture launches two shells from the GUI, selects one through process search,
and releases both independently while keeping the shells alive.

## Routed shell

The Applications launcher offers **Shell** when selected routing is available.
It launches the system `cmd.exe /D /K` as the current user in a new console,
using the same suspended-child transaction as **Launch through Skewer**.
No child code executes until the selected routing generation is Active.
The launcher fields are ignored for this action; `/D` disables command prompt
AutoRun commands. Release leaves the shell running, without selected routing.
New descendants are tracked; singleton handoffs to existing applications outside
the selected group are not covered. Closing Skewer does not terminate the shell.

Native process tests cover dedicated-console creation and suspended execution.
The disposable-service desktop fixture verifies Shell selection and preservation
of the command prompt after Release.

## First-release scope: lab routing, not security isolation

Use WinDivert for interception and Wintun/Tuntom for transport. The interception
service must outlive the GUI. While it remains running, tunnel failure must keep
selected traffic blocked. If the service exits or crashes, its WinDivert handles
close and their filters disappear: applications may communicate through normal
host routes. Automatic service restart does not eliminate this exposure window.
This limitation is accepted for laboratory/testing use, not as a security boundary.
The service implements whole-host IPv4 routing and a selected process's fresh
corroborated IPv4 TCP and UDP traffic. New TCP and uniquely bound UDP descendants
of a routed launch inherit a service-owned Job Object and are independently
owner-checked. Manual Attach also adopts a complete live same-owner descendant
tree. The remaining protocol and coverage limits below are release gaps, not a
claim that routing is unavailable.

Selected-process transport loss retains the same NETWORK capture handle and
whole-host loss retains its independent physical-egress guard. Both retire owned
state and retry with bounded backoff. Only a fresh authenticated, healthy
generation clears `Blocked`; GUI lifetime is not involved.

A custom WFP callout driver is deferred beyond the first release. Neither its
build nor a live kernel experiment is a gate for the WinDivert implementation.

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
| First attach/launch | Establish service-owned interception before admitting selected traffic |
| Tunnel preparing | Block; an adapter existing is not evidence of a working tunnel |
| Verified session and data path | Allow only the selected tunnel path and explicit configured exemptions |
| Peer loss, stale stats, expired lease, adapter loss | Block; never fall back to the host default route |
| Transport fails while interception service lives | Keep selected traffic blocked |
| Interception service exits or crashes | Filters disappear; direct egress may resume; report unavailable |
| Reconnect | Stay blocked until the replacement session and data path are verified |
| Old worker reports ready | Ignore it after session replacement or explicit Disable |
| GUI closes or crashes | Service continues; do not release selection or remove interception |
| Explicit Disable | Stop routing while retaining protection for still-selected applications |
| Explicit application Release | Deliberately return that application's future traffic to normal routing |

Unselected applications must remain unaffected. Auto mode may initially choose
a known direct lab route, as Linux does. Once a tunnel has been selected, its
loss must not silently switch back to direct mode. User-authorized mode changes
are distinct from automatic recovery.

The Windows GUI implements that admission rule without a runtime fallback:
Auto chooses Direct only when a canonical gateway is configured at Start;
otherwise it requires paired Tuntom. Invalid non-empty gateway input blocks
activation instead of silently choosing the tunnel. Native SCM/GUI integration
verifies that closing the panel after Auto selected Direct leaves the generation
active until an explicit Stop.

The controller, tunnel endpoint and control plane must not be routed back into
their own tunnel. Application identity must resist PID reuse and preserve
instance boundaries. An executable-path-only firewall rule is not by itself
equivalent to selecting one running application instance.

## Whole-host scope

Whole-host routing is independently selectable from direct-next-hop versus
tunnel transport. Application mode must continue to leave
unselected applications alone; whole-host mode intentionally includes their host
traffic after explicit authorization. Forwarded VM/bridge traffic remains a
separate feature. See the whole-host acceptance checklist in `TODO.md`.

Direct mode installs owned IPv4 covering routes only after validating that the
gateway is on-link, and keeps IPv6 blocked for the generation. It requires no
tunnel credential, but the command channel remains bound to the installed
service owner. Direct mode passed real HTTP/HTTPS and exact route/DNS rollback
in the disposable Windows VM; this is lab routing, not a persistent kill switch.

Tunnel activation must first retain a verified underlay route to the peer via
the current gateway/interface, then establish narrowly scoped transport and
control-plane exemptions, verify the tunnel data path, and finally admit host
traffic to it. A protected retry withdraws old owned routes and rediscovers the
physical interface and gateway while the guard remains armed. Endpoint
relocation still needs its own control-plane transaction. An exemption is not
permission for arbitrary applications to bypass through the same peer IP. DNS
needed after protection is active requires an explicit bounded transaction,
distinct from normal host DNS traffic.

For installation, a hostname endpoint is resolved before elevation and before
protection is active. One deterministic usable IPv4 address is pinned into the
SCM configuration while the original hostname remains the pairing identity.
This is not runtime relocation: an installed active generation never changes
peer from an ambient DNS answer.

The worker owns routing/protection independently of the GUI. Tunnel failure
must not restore the ordinary default path while protection is active. Explicit
Release host intentionally restores normal routing; pause keeps traffic blocked.
Rollback removes only owned changes and must not overwrite newer DHCP/VPN/admin
state. The WinDivert owner-failure limitation still applies and must be measured
for this scope too; this feature does not promise a persistent kernel kill switch.

Whole-host IPv4 tunnel routing is enabled only by an explicit authenticated
service command. Its real route, DNS, tunnel-loss and cleanup tests run in an
isolated VM with a management-path exception. Direct-next-hop host mode and IPv6
tunnelling remain unimplemented.

The authenticated routing IPC reports its authoritative phase, generation,
scope and selected PID/birth identity. The GUI restores that state after restart
and never stops the service merely because its window closes. Selected launch
starts the process suspended and releases it only after the service reports
Active. Manual Attach is available with an explicit warning that existing
sockets retain their old path.

## Windows implementation order

1. Run the existing platform-independent policy and protocol tests on Windows.
2. Port Tuntom's OS boundary: TUN packet I/O, UDP sockets, polling, randomness,
   helper invocation and process lifetime. Reuse the protocol/crypto core.
3. Use Wintun for the L3 adapter; a privileged service owns adapter, routes and
   lifetime. The unprivileged Qt GUI is only a client of authenticated local IPC.
4. Verify paired transport and data-path probes in the development VM using
   narrow test routes, without replacing the machine's default route.
5. Add per-application enforcement and diversion using service-owned WinDivert handles.
   Do not expose Attach until both IPv4 and IPv6 bypass behavior is tested.

Wintun supplies packet I/O, not application selection or a kill switch. WFP
dynamic-session objects are deleted when the owning session closes: a dynamic
block filter alone therefore cannot provide protection after owner failure.
The isolated `traffic::AppImageBlock` primitive now implements persistent
block-only image rules independently of any tunnel. Its scope is deliberately
all instances of an executable, not one selected process. Instance-level
matching and interception remain to be implemented and tested. The image guard
is experimental, not the selected first-release enforcement backend.

## Acceptance tests

The [first-packet experiment](FIRST_PACKET.md) confirms that a WinDivert SOCKET
filter can deny fresh TCP/UDP attempts for one PID, but new connections become
allowed after its owner is killed. Preserve this test to document the accepted
service-lifetime limitation. Resolve first-packet ownership and interception
before enabling application Attach.

`tunnel_contract_test` runs the actual shared Linux policy helpers on both OSes:
all route-mode combinations, endpoint validation, session-key vector, stale and
malformed telemetry, and reconnect eligibility/backoff. These are policy tests,
not proof of kernel enforcement.

Before expanding the current release scope, packet-level integration tests must capture
the physical egress and verify no direct leak during tunnel loss with the service
alive, GUI restart, adapter deletion, lease expiry and reconnect. Test service
termination separately: direct connectivity may return, and the GUI must report
the service unavailable rather than protected. Exercise TCP, UDP,
IPv4, IPv6, existing sockets, spawned children and PID reuse. Include DNS through
the system resolver; shared resolver traffic must not become an unnoticed bypass.
Also verify another unselected application retains normal connectivity and an
explicit Release affects only the intended instance. Reboot persistence requires
its own test if protection is advertised across reboot.

The VM routed-application smoke forcibly terminates the GUI after a selected
launch, then performs a new HTTPS request from its routed descendant. It verifies
the same service generation remains Active, restarts the GUI, recovers the
authoritative selection and releases it explicitly. This covers GUI crash and
restart without treating GUI lifetime as routing ownership.

## References

- Tuntom: `docs/PROTOCOL_V5.md`, `src/tun_device.hpp`, `src/udp_endpoint.hpp`.
- Linux: `src/tuntom_process.cpp`, `src/tuntom_routing.hpp`, `src/net_helper.cpp`,
  `src/routing_guard.hpp`, `tests/routing_guard_packet_test.py`.
- [Wintun API](https://git.zx2c4.com/wintun/about/)
- [WFP object lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/best-practices)
