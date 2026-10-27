# First-packet decision: experiment and design boundary

## Verified in the development Windows VM

The opt-in `tests/first-packet-live.ps1` runs a same-user fixture with a retained
process identity. All traffic is loopback, using fresh TCP/UDP sockets and
ephemeral ports, for both IPv4 and IPv6. No default route, browser or persistent
WFP policy is changed. The fixture waits on named events between three rounds:

1. Baseline: TCP connections and UDP datagrams are delivered.
2. Install WinDivert SOCKET `DROP | RECV_ONLY`, matching only the fixture PID,
   `CONNECT`, and TCP/UDP. TCP reports `WSAEACCES`; the first unconnected UDP
   datagram is not delivered within the receive deadline. A separate instance
   of the exact same executable still delivers all four traffic classes.
3. Forcibly terminate the retained filter-owner process. The same fixture PID
   opens fresh sockets again: all four traffic classes are delivered.

Result: **per-PID rejection of a new operation works, but protection disappears
after filter-owner termination**. The experiment intentionally confirms this
limitation; a passing test does not certify a kill switch. UDP send success alone
is not proof of delivery, hence the listener-side assertion. This is not a
physical-interface capture, reboot test, existing-socket test or child-process test.

Build with `SKEWER_WINDOWS_FLOW=ON`; place `first_packet_test.exe` and
`app_egress_guard_test.exe` beside the official WinDivert 2.2.2-A x64 files in
the VM test directory. The script checks the DLL/SYS hashes and driver signature.
Run elevated as the fixture user. It terminates only its own retained child
processes, and the experiment helper has a 60-second fallback lifetime. Never
use that ephemeral helper as production protection. It is excluded from CTest.

## Why FLOW plus a PID cache is insufficient

### NETWORK packet-path experiment

`tests/packet-divert-live.ps1` runs `packet_divert_test.exe` against the verified
official WinDivert DLL/driver. The elevated VM-only fixture binds exclusive UDP
loopback endpoints, opens a NETWORK filter for their source/destination ports
and address family, then sends its own payload. Both IPv4 and IPv6 passed on
the Secure Boot development VM:

- The receiver does not get the captured datagram before reinjection.
- Reinjection with preserved metadata and calculated checksums delivers the
  exact payload.
- Withholding reinjection drops the next datagram within the receive deadline.

The script bounds the child lifetime to 45 seconds and cleans up only that
retained process. No routes or persistent policies change. This establishes the
basic capture/send path, not global process ownership, physical egress, tunnel
forwarding or service lifetime. It is deliberately excluded from CTest.

The fixture now starts a selected-process FLOW observer before socket creation
and decodes each held UDP packet through the real packet parser. Both address
families correlate to the fixture's PID and creation time while delivery remains
held, including reverse tuple lookup. This does not establish uniqueness against
unobserved processes sharing a tuple.

For TCP, the initial FLOW-only experiment did not resolve ownership within two
seconds while holding the SYN. Do not depend on an established-FLOW event to
identify the first TCP packet. A passive SOCKET CONNECT observer opened before
connect provides PID and endpoints matching the held SYN on both IPv4 and IPv6.
The final test asserts that match and that the listening socket is not ready to
accept while the SYN is held. It does not complete/reinject a TCP handshake.
CONNECT attempts remain separate from established FLOW records; the fixture
reuses only endpoint normalization, not FLOW-cache insertion semantics.

The reusable `FlowObserver::Mode::ConnectAttempts` now supplies these events
from a passive SOCKET handle. It consumes the same pinned, authenticated
process selection as the FLOW observer, supports cancellation and process exit,
and labels events explicitly `ConnectAttempt`. The first-SYN fixture compares
its output with the held IPv4/IPv6 SYN as well as the independent raw SDK read.
A regression test rejects CONNECT records in the established-flow index.
This is observation, not a blocking/resumable connect hook. Socket lifecycle,
ambiguous ownership and missing-event policy remain routing integration work.

`SocketLifecycle` additionally observes SOCKET CLOSE. `SocketAttemptIndex` keeps
a separate diagnostic CONNECT/CLOSE epoch with bounded entries and closed
tombstones. CLOSE uses process identity plus endpoint ID, not potentially absent
address fields. Older CLOSE events are ignored and delayed CONNECT cannot revive
a closed endpoint. Unknown CLOSE invalidates the epoch conservatively, including
closes for sockets predating observation or sockets without an observed CONNECT.
Shared tuples remain ambiguous. This index is not yet the routing authority;
bound/listening sockets, UDP reuse and observation loss still need integration.

Next integration must handle bounded waiting, unknown and ambiguous ownership,
process exit/reuse, socket lifecycle, wildcard/shared endpoints and non-loopback
traffic before these observations can drive application routing.

### Captured packets through encrypted transport

With the Tuntom pump enabled, the fixture carries captured UDP IPv4/IPv6 packets
through an encrypted local UDP tunnel round trip before reinjection. An
unconfirmed tunnel discards the datagram; its destination must remain unreadable.
`PacketQueue` supplies bounded worker-owned buffers, explicit backpressure and
terminal stop. It does not infer ownership or provide a direct-network fallback.

A separate TCP test captures both directions of an exclusively bound loopback
port pair. After holding the first SYN, it carries every captured packet through
encrypted transport before reinjection, completing the handshake and exact
bidirectional payload for IPv4 and IPv6. Each round trip uses a fresh test
session: this is deliberately not a production relay loop.

These VM tests passed. They prove composition of capture, encrypted transport
and reinjection, not remote internet routing. The peer is a local echo fixture;
capture uses fixture-owned ports, not general application classification.
Browser Attach remains disabled. Physical-egress leak tests, process/socket
ownership, return-path mapping and the persistent routing loop remain required.

### Ownership remains a separate integration gate

The [WinDivert layer contract](https://reqrypt.org/windivert-doc.html#divert_layer)
has distinct capabilities:

| Layer | PID metadata | Blocks | Reinjection |
| --- | --- | --- | --- |
| FLOW | Yes | No | No |
| SOCKET | Yes | Yes (operations) | No |
| NETWORK | No | Yes (packets) | Yes |

SOCKET blocking rejects an operation; it is not a queue from which a successful
connect can later be resumed or rewritten. Adding a NETWORK tuple filter after a
FLOW event cannot establish a first-packet guarantee. Capturing a broad packet
set before any application starts is a different design, with global queuing,
unknown-owner handling still required. Protection after service failure is outside
the accepted first-release lab scope.
Our diagnostic flow index is not that protection.

The existing persistent image guard also cannot be treated as per-instance
protection: it blocks every instance of that executable. Removing it to allow
the chosen process creates an authorization gap, not a safe handoff.

## Deferred alternative: custom kernel guard

This section records a possible later security-oriented design, not the active
implementation plan. The first release uses WinDivert and accepts loss of its
filters when the owner service terminates. Do not load or package this prototype
for that release. See [the active contract](TUNNEL_PARITY.md).

The [build-only ALE prototype](driver/README.md) now compiles with MSVC/WDK.
It has not been installed or exercised in kernel context; the properties below
are not established by compilation or its portable decision tests.

For strict per-instance selection, investigate a small WFP callout at ALE
authorization before implementing a general packet forwarding loop. Microsoft's
[asynchronous classification contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously)
supports pending new ALE authorization, then completing and deciding during
reauthorization. Non-TCP data may also need to be cloned/retained and reinjected;
FLOW_ESTABLISHED is not an asynchronous authorization point.

A future strict kernel guard would need to establish these properties:

- Kernel-bound process identity, with PID reuse, selection and lifetime handled
  explicitly; no trust in a delayed user-mode PID-to-tuple observation.
- Kernel-side default deny for selected instances when the controller disappears.
- Bounded pending decisions, timeout-to-deny and no synchronous user-mode wait
  inside classify callbacks. Reauthorization is handled separately.
- A proved path for both initial and subsequent packets through the tunnel;
  granting connect is not proof that its route is the selected tunnel.
- Existing sockets, process descendants, shared DNS and IPv6 covered or visibly
  rejected as unsupported, never silently routed outside protection.
- Physical egress capture during first connect, tunnel/helper failure and recovery.

[ALE connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
is another WFP callout option if we choose a local connector. It needs redirect
records/context, loop prevention, and explicit TCP/UDP handling; it is not merely
a WinDivert flag. We have not implemented or selected that forwarding architecture.

A custom callout introduces WDK build, signing, installation, upgrade and recovery
work. This experiment does **not** install a custom driver, change Secure Boot,
enable test signing, or prove production driver persistence. Those are separate
decisions; no security setting should be weakened implicitly to run the prototype.

### Independent TCP ownership evidence

`captureTcpOwners()` collects both IP Helper owner-PID tables across processes,
with bounded allocation and retries. `tcpOwnerCandidates()` preserves competing
PIDs for an exact outbound tuple; it never turns a table row into an authenticated
process identity. IPv6 scope collisions are retained conservatively.

The Windows VM fixture verifies that the selected PID appears while its first
IPv4/IPv6 SYN is held by WinDivert. Synthetic tests cover competing owners,
duplicates, direction, port mismatches and rejection of UDP queries.

This is corroborating evidence only: the tables are not atomic with packet
capture or each other, and PID reuse, compartments and socket lifecycle races
still require policy. No production routing decision consumes these snapshots
yet. UDP/shared sockets require separate handling.

### UDP bind candidate policy

`udpOwnerCandidates()` is a pure matcher over supplied bind rows, not a
production owner resolver. It retains both exact and
wildcard binds on the source port, deduplicates known PIDs, and explicitly reports
matching rows with unavailable ownership (PID zero). Remote destinations cannot
narrow a bind-only table. Native IPv6 wildcard and IPv4-mapped binds remain
possible IPv4 competitors because the table does not expose `IPV6_V6ONLY`.

Inputs are canonical outbound L3 tuples; reverse inbound packets explicitly.
Scope and compartment information is intentionally not used to erase possible
competitors. Even a single candidate is not authority to release a packet: bind
ownership, socket sharing and current sender identity are different concepts.
Synthetic tests cover both families, wildcard/exact collisions, duplicate PIDs,
unavailable owners, mapped binds and unrelated ports/addresses.

`captureUdpOwners()` reads both Windows owner-PID tables with bounded allocation
and retries. Failure of either family rejects the complete snapshot; PID zero
is preserved as unavailable ownership. Collection timestamps describe the
observation interval, not a validity lease. Live VM tests verify wildcard binds
for both families and check the fixture PID against a datagram held by WinDivert,
alongside the existing FLOW correlation and encrypted transport tests. These
tests do not establish general ownership for shared sockets. A production policy
combining lifecycle events, snapshot age and ambiguous/unknown owners remains
to be integrated; the snapshot alone never releases a packet.
