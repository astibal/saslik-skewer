# Windows tunnel parity contract

### Protected pause during live recovery

`tests/selected-pause-live.ps1 -RecoveryPeer <IPv4>` exercises a disposable
`SkewerRouting-Test-<GUID>` service against a real paired appliance. It blocks
only that service's UDP data transport (ports 40001-40255), waits for Blocked,
requests Pause, restores the path, and requires repeated paused status and failed
HTTPS until explicit Resume. The selected generation must remain unchanged and
HTTPS must succeed after Resume. This scenario passed in the development VM.

The test exposed command starvation during the authentication handshake: packet
polling correctly waited for readiness, but pause/selection commands waited with
it. A separate worker-thread control poll now remains responsive before readiness
without admitting packets. The native paired-tunnel regression also checks this
ordering with no authenticated peer. No GUI lifetime or owner-crash guarantee
changes are implied.

Validation note: the paired-tunnel test failed with `Unexpected renewal result`
when run concurrently with the live interception fixture, then passed in an
isolated run. The cause of that concurrent failure is not established; serialize
these network fixtures rather than treating this run as concurrency coverage.

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

The Applications and Connections views distinguish Active, Blocked, transition,
idle and unavailable states. Whole-host policy is labeled as policy (including
its configured exemptions), not proof that every displayed socket is tunneled.
IPC status carries an immutable snapshot of roots and live Job member identities
(PID plus creation time). The packet worker refreshes membership every 250 ms;
GUI polling adds its normal observation delay. Confirmed descendants receive
badges even when their windows put them in a different visual application row.
The bounded response includes up to 1024 members and a visible truncation flag.
Unlisted processes remain unconfirmed: absence from a sampled or truncated list
is not proof of direct routing. Release still targets roots, not individual Job
members.

Add revalidates the configured owner and process creation time. Remove accepts
an exact previously selected root, including an exited root with live children.
It retires that tree's packet queues, reverse mappings and guards without killing
applications or stopping other selections. The final removal retires routing.
Overlapping trees are rejected rather than giving Release ambiguous semantics.

Full connect guards apply during initial enrollment, explicit Attach and recovery.
New descendants of an Active group use the already armed packet capture and keep
unsupported-protocol guards, but do not receive a temporary all-connect denial.
The native HTTPS descendant fixture starts eight fresh curl processes in one
generation without sleeps or retries to exercise this admission boundary.

Current status (operation 11) and Pause/Resume (9/10) use version 9: version-8
membership followed by one flags byte for pause capability and confirmed pause.
Unknown bits, paused-without-capability and capability outside selected scope are
rejected. Legacy membership status (8) retains version 8. Operation 7 and other
extended mutation replies retain version 7; older operations retain version 6. New GUI/CLI clients
require an upgraded service. Status responses validate member counts, duplicate
identities and reserved padding before exposing the snapshot.
Mutation requests are not automatically retried after IPC loss: inspect status
because a request may already have been applied. The disposable-service fixture
tests concurrent HTTPS, independent Release, fresh HTTPS from the remaining tree,
unchanged generation and rejection of stale-generation mutations. The desktop
fixture launches two shells from the GUI, hides their process rows, selects one
through the routed-group picker, and releases both independently while keeping
the shells alive. The picker preserves the exact root identity across inventory
and status refreshes and lists roots even after their original process exits.
Native process tests verify that releasing an exited root preserves its surviving
children. Choosing another process-tree row returns Release to that row's root.

## Routed shell

The Routing tab labels its global action by authoritative scope: **Release host**
or **Release all applications**. Its tooltip and accessible description explicitly
state that this restores normal connectivity, not a protected pause. Releasing
one group remains a separate Applications action. The interactive smoke checks
the selected-scope label after GUI recovery before releasing only that group.

Launcher feedback follows the exact process handle returned by Windows, using
an event notification rather than PID polling. When the latest launched root
exits, its success message is replaced by the exit code and a possible
single-instance handoff warning. This does not infer a handoff destination or
adopt an older process. Surviving selected descendants remain service-owned;
closing the GUI or observing root exit does not send Stop/Release. The desktop
fixture includes a fast `exit 7` child before its routing and GUI-crash checks.

The Applications launcher offers **Shell** when selected routing is available.
It launches the system `cmd.exe /D /K` as the current user in a new console,
using the same suspended-child transaction as **Launch through Skewer**.
No child code executes until the selected routing generation is Active.
The launcher fields are ignored for this action; `/D` disables command prompt
AutoRun commands. Release leaves the shell running, without selected routing.
New descendants are tracked; singleton handoffs to existing applications outside
the selected group are not covered. Closing Skewer does not terminate the shell.

The native process-group regression includes an existing singleton broker and a
new suspended launcher selected before execution. The launcher signals the broker
through a named event and exits successfully. The broker acknowledges the request
and remains alive, but must remain outside the routing selection before and after
handoff. This verifies the membership boundary and supports the launcher's exit
warning; it does not claim interception of the broker's traffic. Users must select
that existing instance explicitly or launch a genuinely independent instance.

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

Protected pause is available through `skewer-routing-control pause SERVICE
GENERATION` and `resume` for selected applications, and separate Pause/Resume
buttons on the Routing tab. They require authoritative service capability and
state; Release remains a distinct action. Authenticated operations 9/10
reject stale generations. The service waits for packet-worker acknowledgement;
an uncertain response must be reconciled through status, never blindly resent.
Its packet layer keeps capture active, discards queued data in
both directions and preserves flow identities for a healthy resume. Native
WinDivert tests verify that unrelated Direct traffic continues, selected packets
do not bypass the tunnel, unsupported IPv6 remains blocked, and Resume cannot
revive an epoch retired by transport failure. Pause intent survives replacement
packet sessions. The native paired HTTPS fixture checks successful transfer,
pause blocking, stale Resume rejection and recovery in the same generation.
The desktop fixture checks both buttons against service state without changing
the routing generation. It terminates the GUI while paused, verifies that the
service retains protection, and reopens the GUI to recover the enabled Resume
action without implicitly resuming. Controller regressions also cover Stop
cancelling an unclaimed request and worker failure completing an already claimed
request with an error instead of retaining a false protection claim.
Whole-host pause is not currently supported.

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

`tests/selected-ipv6-egress.ps1` requires an idle paired service and an HTTP
listener on another host reachable over IPv6. For example, on the development
VM (replace the scope ID with its Ethernet interface index):

```powershell
.\selected-ipv6-egress.ps1 -Url 'http://[fe80::534b:2026%254]:18765/'
```

The baseline must succeed before selection. A suspended launcher starts the
probe under routing protection; its curl descendant must fail to connect while
an unrelated curl still succeeds. Explicit Release must restore connectivity
for that same application. Results remain in a uniquely named temporary
directory. The fixture does not change host routes or DNS. Verified on the
Rhino Windows VM against an isolated network-namespace HTTP listener attached
to its virtual LAN. On 2026-10-29 the same fixture also passed with ULA
`fd53:534b:2026:1029::2/64` on the VM and a namespace HTTP listener at
`fd53:534b:2026:1029::1`, using a disposable paired service built from `89716ca`.
The temporary VM address, service and namespace were removed afterwards; no
default gateway or DNS change was needed. With a reachable ULA peer, invoke:

```powershell
.\selected-ipv6-egress.ps1 -Service YOUR_PAIRED_TEST_SERVICE -Url 'http://[fd53:534b:2026:1029::1]:18081/'
```

These are external link-local and on-link ULA TCP checks, not proof of public
IPv6 internet reachability, routed IPv6 or UDP behavior.

`tests/selected-existing-ipv6.ps1` additionally checks an IPv6 TCP socket opened
before Attach. Start a fresh marker peer on a separate, isolated IPv6-reachable
host for each run (Python is needed only on that test peer):

```sh
python3 ipv6-marker-peer.py fd53:534b:2026:1029::1 18082
```

```powershell
.\selected-existing-ipv6.ps1 -Service YOUR_PAIRED_TEST_SERVICE -Address fd53:534b:2026:1029::1 -Port 18082
```

The child must complete an echo before Attach. Once Active, it writes a protected
marker on that same socket. An unselected control connection queries the peer's
counter: no protected byte may have arrived. After Release, the original socket
must deliver and receive a new marker. Retransmission of the previously blocked
byte after deliberate Release is allowed. This passed against an external ULA
namespace peer on 2026-10-29. The fixture requires an idle paired service, retains
child logs and removes only its own selection/process; it does not configure
addresses, default routes or DNS. Recreated peers should retain a stable MAC or
clear only their fixture-specific stale neighbor entry before the baseline.

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

## UDP owner snapshot regression (2026-10-29)

The per-process resolver now requires a unique UDP bind row before tunnelling,
even when the socket observer reports a matching lifecycle. Multiple binds owned
by the same PID must not become unique through PID de-duplication: an observer
attached later may not have seen all existing sockets. Ambiguous selected traffic
is held, while positive evidence excluding the selection retains the existing
unrelated-traffic policy. The owner-candidate test covers duplicate same-PID rows,
missing evidence and unknown owners for both address families. Its native Windows
run also creates two live wildcard sockets sharing one port in the same process,
checks that both rows survive PID de-duplication, then closes the competitor and
requires unique evidence again (IPv4 and IPv6). These checks alone do not prove
physical-egress behaviour for live shared UDP sockets.

The full selected-service VM integration passed with the updated service,
including selected root/descendant HTTPS and DNS, unique pre-Attach UDP, existing
TCP handling, independent group Release, GUI crash survival and unchanged host
routes and DNS after cleanup.

## Packaged regression checkpoint (2026-10-29)

The complete Windows ZIP built from `ecd34b1` passed all 44 native test programs,
archive/dependency verification, per-user install/uninstall, version checks and
GUI startup in the development Windows VM. Native window visibility checks inside
the process test skip on the noninteractive SSH window station; this checkpoint
does not replace the separate interactive routed-application smoke. Nor does it
prove live multi-adapter failover or physical-egress coverage for shared UDP.

## External shared UDP delivery (2026-10-29)

`selected-shared-udp.ps1` and `udp-marker-peer.py` add a separate live integration
gate. Start the peer on an explicitly chosen IPv4 address/port outside the VM,
then run the PowerShell fixture against an idle paired disposable service with
the same `-Address` and `-Port`. The fixture owns only its child and selection;
the caller owns peer/service setup and cleanup. Do not share a peer instance
between tests because its counters intentionally persist for the whole run.

Two same-process UDP sockets share a wildcard port before Attach. Both must
deliver baseline markers to the external peer. After Active, a third socket
binds the same port: the observer now has fresh lifecycle evidence but cannot
have observed the original binds. All three send protected markers. An unselected
TCP control connection independently checks that none arrived, then explicit
Release must restore delivery from all three sockets. The test passed against
the KVM host's IPv4 bridge endpoint using the updated disposable Windows service.
It proves this shared-bind delivery case, not arbitrary destination, adapter
failover or service-crash isolation. The accepted WinDivert lifetime limit remains.

## Live dual-adapter failover (2026-10-29)

`native-routing-service-live.ps1 -FailoverInterface INDEX` exercises loss of the
caller-designated disposable secondary NIC. The peer pin must initially use that
NIC. The test disables it while the service remains alive, requires an Active
replacement peer pin on another physical interface in the same generation, then
checks real HTTPS before explicit Stop. Cleanup re-enables the NIC and verifies
default routes and DNS. DHCP may recompute that NIC's route metric on re-enable;
the test preserves this OS-owned change rather than overwriting it. Other default
route fields and other interfaces' metrics remain compared exactly.

This passed on two e1000e adapters on the development VM's isolated KVM network,
with the preferred secondary interface metric 20. The temporary NIC was removed
afterwards. This verifies interface loss, not a different gateway, VPN coexistence
or peer-address relocation. An earlier metric-1 run timed out in ordinary DNS
before the failover step; the DNS preference fix below addresses that regression.

## Owned tunnel DNS preference (2026-10-29)

Windows considers interface preference when choosing a DNS server. Wintun's
automatic metric was 5 in the VM, so a physical NIC manually set to 1 took
priority despite tunnel DNS being configured. Its physical DNS traffic was
correctly blocked, but application resolution could time out. Whole-host DNS
setup now disables automatic metric on the exclusively owned tunnel, sets metric
0 and verifies the retained native value before activation. Deleting the adapter
retires both DNS and metric settings; physical DNS, interface metrics and global
resolver policy are not rewritten. This does not grant a DNS bypass in the guard.

The native regression now clears DNS cache before each of three ordinary HTTPS
requests. All passed with physical metric 1, followed by actual NIC loss,
replacement peer pin, HTTPS recovery and route/DNS cleanup. This is evidence for
the tested configuration, not a claim to override enterprise NRPT rules or every
possible competing VPN configuration.

Reference: [Microsoft VPN name resolution](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution).

## Installed-service upgrade checkpoint (2026-10-29)

The disposable upgrade test now covers a paired tunnel-ready service upgrade,
in addition to conversion from Direct-only configuration. Restarted services must
be Idle and have no borrowed credentials; a fresh handoff from the existing user
DPAPI store must restore pairing without a new invitation or starting routing.
The test verifies the installed binary hash and complete disposable removal.

After this passed, the development VM's real `SkewerRouting` installation was
upgraded to the service built from `25556a1`. Its endpoint, DNS, owner, management
exception and automatic startup configuration were preserved. The installed hash
matched the tested package, pairing was handed back from user storage, and the
service remained Idle. This checkpoint is a development deployment, not a public
release or evidence that all remaining parity gates are complete.

## References

- Tuntom: `docs/PROTOCOL_V5.md`, `src/tun_device.hpp`, `src/udp_endpoint.hpp`.
- Linux: `src/tuntom_process.cpp`, `src/tuntom_routing.hpp`, `src/net_helper.cpp`,
  `src/routing_guard.hpp`, `tests/routing_guard_packet_test.py`.
- [Wintun API](https://git.zx2c4.com/wintun/about/)
- [WFP object lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/best-practices)
