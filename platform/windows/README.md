# Windows backend and shared application UI

## First-release direction and limitation

The selected backend is WinDivert interception with Wintun/Tuntom transport,
owned by a privileged service independent of the GUI. Whole-host IPv4 and a
selected process's fresh corroborated IPv4 TCP and UDP are integrated. New
descendants of a routed launch inherit selection through a Windows Job Object.
Manual Attach adopts descendants whose complete, live, same-owner parent chain
still leads to the selected root. UDP descendants additionally require exactly
one matching owner-table bind row. IPv6, orphaned or handed-off processes,
ambiguous shared binds and already-open sockets are not covered by
selected-process mode.
The custom kernel callout prototype is deferred and will not ship in the first
release. No custom-driver test-signing setup is required for that release.

Skewer is a laboratory routing and testing tool, not a security isolation
boundary. The service must block selected traffic during tunnel failure while
it remains running. If the service exits or crashes, its WinDivert filters
disappear and applications may communicate through normal host routes. Automatic
restart cannot remove that exposure window. Closing the GUI must not stop the
service. These behaviors require integration tests before they are advertised
as implemented. See [the contract and acceptance tests](TUNNEL_PARITY.md).

## Current implementation

### Current-user CA trust

The Windows **CA Trust** page downloads the CA over the existing authenticated
paired channel, validates PEM structure, CA Basic Constraints and time validity
with Windows CryptoAPI, and compares exact DER bytes against
`Current User\\ROOT`. The user can explicitly install or remove only that exact
certificate. Windows may show its native protected-root confirmation; Skewer
does not bypass it. System-machine and application-specific stores remain
untouched. The interactive VM smoke test is intentionally read-only: it verifies
download, native validation, fingerprinting and store inspection without
changing trust.

### Native whole-host service integration

The Windows desktop has a **Routing** tab for an installed service: stored
pairing handoff, asynchronous state, generation-bound Start/Stop, and explicit
Idle/Starting/Active/Blocked/Stopping/Failed feedback. Periodic status reads do
not toggle controls; unknown state disables mutations. A click arriving during
a read is queued once with its original generation, never silently retried.
The panel remembers the successful service/endpoint choice. Closing it cancels
only local IPC, not routing. The Applications page can attach one running
process or launch it suspended and resume it only after the service reports
Active. The panel can explicitly install or upgrade the service through UAC;
an absent, unpaired or incompatible service never enables routing controls.

`routing_panel_test` checks missing-service responsiveness and bounded local
cancellation. `native-routing-service-live.ps1 -GuiClient` uses the real Qt
buttons to pair/start, closes the panel, then verifies continued system DNS and
HTTP/HTTPS through the SCM service. This passed with `-TestTunnelLoss` on the
Windows VM on 2026-10-28, including fail-closed behavior and cleanup. It tests
widget behavior, not final visual parity or a finished installer.

`routed-application-smoke.ps1` goes further for selected mode: it forcibly
terminates the GUI after routed launch, waits for a fresh descendant HTTPS
request, confirms the service generation remains Active, restarts the GUI,
recovers the selection and performs explicit Release. The complete SCM fixture
then covers root, new and pre-existing descendant HTTPS plus root/descendant
DNS/UDP. This passed on the Windows VM on 2026-10-28 with routes and DNS unchanged.

`skewer-routing-service.exe --service NAME OWNER_SID ENDPOINT IPV4_PEER DNS_SERVER
[SSH_MANAGEMENT_IP]` now hosts the real paired runtime under SCM. These arguments
must be administrator-owned service configuration; DLLs are loaded only from
the service installation directory. Pairing is memory-only through the existing
authenticated client. The release ZIP includes the service installer, while the
per-user desktop installer deliberately leaves privileged service installation
as a separate explicit action.

`WholeHostPolicy` snapshots the underlay, rejects existing conflicting /1 or peer
/32 routes, arms the physical-egress guard, assigns the authenticated Wintun
address, waits for transport health, then installs a peer /32 and tunnel /1 routes.
The peer stays outside its tunnel. Cleanup withdraws routes before retiring the
adapter. Physical IPv6 egress is blocked; IPv6 tunneling remains unfinished.
The configured numeric IPv4 DNS server is assigned only to the fresh Wintun
adapter using SetInterfaceDnsSettings (Windows 10 build 19041 or newer); physical
adapter DNS settings are never changed. Adapter destruction removes its DNS
settings. Registration and LLMNR are disabled only on that adapter. Tuple exceptions allow control TCP and protocol UDP ports
40001–40255 to the configured peer. They are not process isolation. The optional
management IP allows SSH replies only and is explicit lab administration policy.

`tests/native-routing-service-live.ps1` installs a disposable real service from
verified driver artifacts in Program Files, hands off saved pairing and tests
plain HTTP/HTTPS with no explicit proxy. It first pre-resolves DNS to isolate
transport checks, then clears the test VM's resolver cache and tests system DNS
and HTTPS without `--resolve`. The TLS CA check is bypassed only by the test curl.
`-TestTunnelLoss` disables only the owned
adapter, requires Blocked while the service remains alive, and verifies direct
HTTP fallback times out. Explicit Stop removes protection after cleanup; the
controller retains Failed for that generation rather than concealing the earlier
tunnel error. The script finally removes the service and checks owned routes,
adapter and unchanged default routes. Binaries are retained for diagnostics.

The DNS-enabled SCM integration passed on the Windows VM on 2026-10-28, including
system resolution, ordinary HTTPS, tunnel loss blocking and owned-resource cleanup.
The per-interface API contract is documented at
https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings.

### Generation-bound routing commands

`skewer-routing-control` is the real headless service client (also the transport
foundation for the desktop controller):

```
skewer-routing-control status SERVICE
skewer-routing-control pair SERVICE skewer://HOST:8766/pair
skewer-routing-control start SERVICE GENERATION
skewer-routing-control stop SERVICE GENERATION
```

Status returns JSON with an opaque string generation. Start/Stop require that
generation; Busy/Stale return a structured reply and nonzero exit status. The
client retries connection establishment only, never a possibly committed write.
Pair reads the existing user-owned DPAPI pairing, verifies the SCM pipe before
decrypting it, and sends a memory-only snapshot through the authenticated handoff.
It never accepts a secret in argv, creates a SYSTEM credential file, or starts
routing implicitly. Use an installed trusted service name, not a remote pipe.

The 2026-10-28 VM test used this client against the real temporary SCM service,
including stored Windows pairing handoff followed by public fixture replacement
while idle. Start/Stop, stale generation, Busy, denied active pairing replacement
and SCM cleanup passed. The fixture did not open a real tunnel. Shared snapshot
tests passed on Windows and the Linux regression suite passed 39/39.

`serveRoutingService` is the shared service command loop, independent of the
test executable. The installed host supplies its trusted `ServiceOwner`, stop event
and paired runner. The loop owns both authenticated pipes and the memory-only
pairing snapshot. It refuses Start before pairing and replacement credentials
while a generation is running or stopping. Its controller is destroyed before
credentials, so SCM stop joins the runner before wiping the pairing. Client
disconnects and malformed requests do not stop an active generation.

`ServiceOwner` stores a canonical Windows SID from administrator-owned service
configuration. It needs no live installer process, logon token or stored user
password. Both the pipe ACL and each authenticated request enforce that SID;
SYSTEM's pipe administration permission does not authorize another owner's
commands. The token overload snapshots the same identity for existing callers.
Never source the configured SID from client request fields. Windows tests cover
closed source tokens, foreign owner rejection, malformed/alias SID rejection,
and reconnecting/pairing after an actual SCM stop/start with the same SID.

`RoutingController` owns an asynchronous runtime independently of IPC clients.
Authenticated start/stop/status commands report Idle, Starting, Active, Blocked,
Stopping or Failed, with a monotonically increasing runtime generation seeded
from the system RNG for each controller lifetime, avoiding reuse after restart.
Mutations require the current generation: delayed STOP from an older client
cannot reach a restarted tunnel, and START while busy never launches a duplicate.
STOP is nonblocking; Stopping persists until the runner finishes protected
cleanup. Status polls reap completed workers without blocking the command thread.

`runGuardedWorker` now publishes a blocked signal when its tunnel session exits
unexpectedly, while retaining the guard. `runGuardedPairedTunnel` passes this
through for the controller; routing readiness is still separate from SCM RUNNING.
The owner-authenticated command transport uses bounded versioned messages and
pins the SCM server before writing, as with the pairing handoff.

`tests/routing-service-live.ps1` connects pairing handoff, command IPC, controller,
and a real session-zero WinDivert handle in one temporary service. It tests
client exit, blocked state, duplicate start, stale stop, restart, and SCM stop.
Its false filter and deliberately failing session change no network policy;
it does not demonstrate working service-owned tunnel traffic. Production adapter
setup, trusted route/guard configuration and GUI integration remain pending.
`routing_control_test` separately covers active state, cleanup wait and fatal
runner failure without using networking.

### Authenticated credential handoff transport

`sendPairingHandoff` / `receivePairingHandoff` use a dedicated, bounded,
message-mode connection. Before any write, the client pins the running own-process
SCM service. The server first reads only PID/birth, verifies the actual pipe
client PID, authenticates its token and compares ownership against the trusted
session owner's token. Only then does it request the credential envelope.
The explicit owner check also applies to SYSTEM, which has pipe administration
rights but is not automatically the intended pairing owner.

The envelope has fixed bounds/version, canonical zero padding and a 32-byte key.
Temporary key buffers are cleared on scope exit. A single deadline covers the
handshake; malformed, cancelled and oversized messages retire the connection.
Acknowledgement means validated delivery, not persistence, tunnel startup or
routing readiness. Endpoint semantics still require `PairedControl` validation.
Production installer, GUI invocation and start/stop protocol are not wired yet.

`selection_auth_test` checks rejection before writing to a non-SCM server and
malformed envelopes. `tests/selection-service-live.ps1 -Handoff` verifies real
user-to-LocalSystem delivery with public fixture credentials; `-WrongOwner`
verifies denial before secret transfer. No actual pairing key or network policy
is used or changed by these fixtures.

### Storage-independent paired control

Windows `PskTunnelControl` now retains one `PairedControl` credential snapshot
for open, renewal and close. User DPAPI storage is read once, not by every
renewal. The explicit-credential constructor supports a future authenticated
service handoff without giving LocalSystem access to the user's pairing files.
It does not itself authorize IPC or persist the handed-off key.

Snapshot keys have bounded length, use separately owned memory, and are cleared
best-effort on destruction. This does not erase caller/TLS copies or protect
against crash dumps. Existing Linux convenience functions retain their previous
per-call loading behavior. The TLS-PSK fixture checks invalid credentials,
enrollment, stale leases, and a complete open/renew/close after removing only
the isolated test pairing file. Windows additionally exercises DPAPI.

### Guard lifetime independent of the tunnel

`runGuardedWorker` supervises the session separately from the physical-egress
WinDivert consumer. A session exception or unexpected return is retained in the
result, but the guard keeps draining and discarding until explicit cancellation.
Cancellation joins the session and requires successful route cleanup before
returning. Cleanup exceptions/failures retry at bounded intervals; they never
authorize direct fallback. A pre-cancelled worker does not start a session.

`runGuardedPairedTunnel` composes this supervisor with the paired packet worker
and native `TunnelRoutes`. The caller must already have armed a trusted guard,
configured the adapter and validated the route plan. An externally changed route
is deliberately unresolved: SCM shutdown may remain pending rather than release
protection. Administrative recovery for that condition is not yet exposed.
Fatal capture failure or process termination still has WinDivert's documented
owner-lifetime limitation; this is not a persistent kernel kill switch.

`guarded_worker_test --live TRUSTED_DLL` uses a real handle with a fixed false
filter to check failed/returned sessions, cancellation and retrying cleanup.
`tests/capture-service-live.ps1` additionally checks that a simulated tunnel
failure leaves its temporary LocalSystem service running until explicit STOP.
These fixtures alter no routing and do not prove packet blocking; whole-host
packet blocking is covered separately by the live experiment below.

This composition is not yet an installed production service or GUI action.
Authenticated start/stop IPC, user-bound pairing credentials and installation
still need integration. GUI routing controls remain disabled until that path is
implemented and tested end to end.

### Native route ownership

`OwnedRoute` is the native IP Helper building block for replacing the live
experiment's PowerShell route setup. It creates ActiveStore IPv4 routes and
never adopts or overwrites an existing route. Explicit cleanup distinguishes
removed, missing, externally changed and failed routes; the future service must
inspect that result while its egress guard remains armed. Destruction is only a
best-effort fallback, not crash recovery.

Cleanup compares writable policy attributes and preserves observed changes.
IP Helper provides no atomic compare-and-delete: simultaneous administrator
updates and identical delete/recreate cannot be distinguished reliably. This is
not a security boundary. Interface defaults are specified explicitly rather
than comparing the API initializer's unspecified values against normalized rows.

Run `owned_route_test.exe --live` only in an elevated disposable Windows VM.
It creates a temporary `203.0.113.254/32` route, sends no traffic, and checks
conflict refusal, explicit/destructor cleanup, already-missing routes and
preservation after an administrator-style metric change. It refuses an existing
fixture route. This test is intentionally excluded from automatic CTest runs.
`TunnelRoutes` groups a bounded trusted route plan, installs in plan order and
withdraws in reverse order. A partial installation rolls back; a retired plan
cannot reactivate. `clean()` remains false for failed removal or an observed
external change, so callers must not treat withdrawal alone as permission to
release their guard. `tunnel_routes_test.exe --live` verifies the native plan
and partial rollback using two TEST-NET /32 destinations.

The paired packet worker accepts an optional `TunnelRoutePolicy`. It activates
only after authenticated transport health, publishes readiness after activation,
and clears readiness before withdrawal. Lease rejection/expiration, transport
health loss, installation failure and cancellation all withdraw before waiting
for pending renewal or closing the lease. Once a routed transport loses health,
that worker terminates rather than silently reinstalling routes. The existing
encrypted loopback test verifies this ordering and failure behavior.

This wires route policy into the packet worker, not yet the production SCM
service or GUI. The caller still supplies validated addressing, interface setup
and an already-armed external guard, which this policy never releases. The live
whole-host PowerShell fixture below remains unchanged for now.

### Whole-host IPv4 live experiment

`tests/paired-tunnel-live.ps1 -WholeHostTest -WinDivertDirectory PATH
-Management IPV4` extends the paired probe with temporary `/1` routes through
Wintun, a pinned `/32` underlay route to the peer, and `host_guard_live` on the
physical-egress deny path. Supply the usual Directory, WintunDll, Endpoint and
Peer arguments; do not combine this mode with ConnectPort. Run only in the
disposable development VM with out-of-band management available.

The guard must arm before routing changes. It drops outbound non-loopback traffic
outside Wintun except the exact peer UDP/control ports and SSH replies to the
declared management address. Exceptions are tuple-based fixture allowances, not
process authentication. IPv6 physical egress is denied, not tunneled. HTTP/HTTPS
use pre-resolved example.com with no explicit proxy or source-interface binding;
HTTPS ignores certificate trust only for this lab test. DNS and public IPv6
forwarding are not covered.

After the bounded tunnel owner exits, HTTP must fail while the guard is still
alive. Cleanup removes only the fixture's exact routes before stopping the guard,
then checks the original default routes and adapter removal. Wintun teardown
also removes its `/1` routes; abrupt script termination may leave the peer `/32`
route, so this is not a production crash-recovery implementation. The guard has
a 90-second safety lifetime and no persistent kill-switch guarantee. No GUI
whole-host control is exposed by this experiment.

Verified on SKEWER-WIN11: HTTP and HTTPS completed through the temporary host
routes without proxy/source binding; after tunnel teardown HTTP timed out with
the guard alive. The guard reported 80 dropped packets (including background
traffic), and the tunnel reported 79 transmitted/23 received inner packets.
An independent post-test route inspection found neither `/1` nor peer `/32`
left behind; ordinary HTTP worked again. The existing Linux tunnel stayed active
and the Windows server-side lease/unit was removed. This is a bounded end-to-end
experiment, not physical-egress packet-capture proof, DNS coverage, CA validation,
or a production service/GUI implementation.

### Selection-bound packet epochs

`SelectedPacketEpoch` connects the service-owned selection registry to the
portable bounded packet queue. It checks the pinned PID/birth and selection
generation before enqueueing and before/after ownership resolution. Tunnel
readiness is sampled on both sides of resolution; failure retires the queue
instead of returning packets for direct reinjection. The readiness callback
must track the same transport epoch, never a replacement tunnel. Registry and
queue must share one worker thread, with registry lifetime enclosing the queue.

`selected_packet_epoch_test` uses synthetic packets and real Windows process
handles to cover successful one-shot transfer, tunnel loss, selection replacement
during resolution, resolver/readiness exceptions and unknown/ambiguous owners.
It does not install WinDivert filters or prove real packet forwarding. A trusted
ownership resolver and the final send-time transport gate remain mandatory;
diagnostic FLOW/SOCKET matches must not be promoted to unique ownership.

### Authenticated routing capability queries

The service-worker `SelectionRegistry` retains already-authorized process handles
independently of IPC connection lifetime. Membership uses PID plus creation time;
each remove/re-add creates a new generation so stale queued work or releases
cannot affect a later selection. Capacity is bounded, dead processes are excluded
from live snapshots, and releasing/destroying the registry never terminates an
application. It has one owner thread and no global locks. This is desired-selection
bookkeeping, not an installed interception policy or a routing readiness signal.

`selection_registry_test` checks duplicate retries, capacity, stale identities,
generations, process exit and non-terminating release using an owned child process.
The live service fixture also retains an authorized long-lived target after the
short-lived selecting IPC client exits. This fixture retention is not a new
production Attach command; GUI Attach stays disabled pending packet enforcement.

`exchangeScopeProbe()` queries application or whole-host scope through the same
SCM-authenticated, bounded IPC exchange as process validation. It derives the
caller identity locally and does not attach processes or modify policy. Both
scopes currently report `ScopeUnsupported`; transport/authentication failures
are separate errors. A process `Verified` reply is never treated as a routing
capability. The live selection-service fixture tests both queries against a
temporary LocalSystem service and verifies clean shutdown. This is backend
integration groundwork, not an enabled GUI routing control.

### Paired control client

`SKEWER_WINDOWS_PAIRING=ON` builds `skewer-control` from the same TLS 1.3 PSK
control implementation as Linux. Use `skewer-control pair -` and paste the
invitation on stdin; `remote-status skewer://HOST:PORT/pair` uses the saved
pairing. This client does not install routes, start a service or create adapters.
Windows pairing files are DPAPI-protected for the invoking user; plaintext files
are rejected. This does not yet give a SYSTEM service access to the credentials:
that handoff must use authenticated IPC, not machine-wide credential storage.

`skewer-control report skewer://HOST:PORT/pair` sends an authenticated presence
report and remembers the successfully validated endpoint for the GUI. The
Windows **Saslik** tab resumes reporting every ten seconds, including while
minimized. Network I/O runs off the UI thread. Stop reporting and closing the
window leave pairing, applications and routing untouched; Saslik marks presence
offline after its report timeout (currently thirty seconds).

The device list is populated by reports, not enrollment alone. Reports contain
the hostname, Skewer version and an exact CryptoAPI observation of the last CA
downloaded from Saslik in `Current User\\ROOT`. No other Windows or
application-private store is claimed. Online presence must not be interpreted
as active application routing. Invitations can be consumed by the protected
field on the Saslik tab or by the pairing command's stdin; they must never be
placed in the endpoint field or command-line arguments.

`client_report_test` covers the minimal report schema, a real Current User Root
observation, and rejection of invitation-bearing endpoints without leaking
their contents.
`tests/client-report-smoke.ps1` runs on the interactive Windows desktop and
checks accepted reports, renewal while minimized, and stop/start controls.

Build the pinned OpenSSL 3.5.9 archive with `sh build-openssl.sh ARCHIVE PREFIX`
inside the cross-build container, then add that prefix to `CMAKE_PREFIX_PATH`
and configure `OPENSSL_ROOT_DIR=PREFIX` and `SKEWER_WINDOWS_PAIRING=ON`.
The script verifies SHA-256 before extraction and
builds static libraries. Qt's unrelated TLS plugins are not used by the PSK
exchange. Distribute the appropriate OpenSSL license with release artifacts.

`pairing_storage_test` checks DPAPI roundtrip, corruption and plaintext rejection.
`tuntom_control_test ENDPOINT` reads its invitation from stdin and exercises
enrollment, repeated open, renewal, close, key rotation and stale-lease rejection.
The Python 3.13+ fixture `tests/pairing-peer.py` listens only on loopback port
18767, stops after the test or 120 seconds, and uses public test credentials.
Forward this port over SSH for a VM test; do not expose it on a LAN. It models
control responses only and is not evidence of real Saslik forwarding.
`tests/pairing-live.ps1 -Directory PATH` runs the storage test, rejects an invalid
PSK, then exercises the control lifecycle against that forwarded fixture.
This sequence passed on the Windows development VM using statically linked
OpenSSL 3.5.9. Linux regression tests passed as well (37/37).

### Paired transport lifetime

`runPairedTunnel()` connects the paired control API to the encrypted packet pump.
One owner manages the lease, readiness and packet I/O; bounded control renewals
run asynchronously so a slow control endpoint does not stall healthy data.
The conservative lease deadline starts before the request, not after its reply.
Expiry, rejection and cancellation clear readiness; a late response cannot revive
the retired owner. Data authorization is checked in both directions at packet
boundaries. The owner closes the remote lease after joining any pending renewal.

The caller must keep its external capture/routing guard armed independently.
This library does not yet connect GUI selection to a deployed routing service,
and it never restores direct routing on failure. A pinned numeric IPv4 peer is
shared by control and UDP transport; IPv6 transport selection remains separate work.

`paired_tunnel_live --live ABSOLUTE_WINTUN_DLL PAIRED_ENDPOINT IPV4_PEER` is an
explicit 45-second developer probe using a pairing saved by `skewer-control`.
It creates an ephemeral adapter, prints authenticated public IP metadata and
cleans up the adapter/lease on exit. `AddressedTunnelControl` configures its
authenticated IPv4 /30 and MTU 1280 through IP Helper before starting the pump.
Existing subnet routes are rejected before assignment; DAD must complete within
eight seconds. Failed setup closes the remote lease. Address cleanup only deletes
the owned address with matching attributes, with adapter destruction as a backstop.
No physical NIC or default route is modified.
Do not expose application traffic until the external guard is installed.

The Windows VM tests cover encrypted loopback payloads, packet-boundary denial
in both directions, cancellation, renewal rejection and continued pumping while
control sleeps. A renewal delayed beyond lease expiry must clear readiness and
stop data before its worker returns. These tests use an injected control fixture;
the explicit paired Wintun probe is covered separately by the live test below.
Linux regressions passed (38/38).

`tests/paired-tunnel-live.ps1` drives the real paired probe. It verifies the
Wintun signature and independently verifies the native /30, MTU, preferred
address state and subnet route on the fresh adapter. It sends three source-bound
pings, and optionally tests HTTPS through Smithproxy using `-ConnectPort 33128`.
The HTTPS test deliberately ignores the MITM certificate trust for this lab
probe only; it does not install a CA or change browser policy. Default routes
are compared before/after and the owned adapter must disappear.

On 2026-10-28 the native addressing path passed on the Windows VM: preferred
/30 address, MTU 1280, owned subnet route, three pings and HTTPS over CONNECT.
The probe reported 47 transmitted and 19 received inner packets; adapter cleanup
passed and default routes were unchanged. This still exercises the developer
probe, not a deployed GUI-to-service routing session.

On 2026-10-27 the Windows VM passed this path against a running Saslik workspace:
`curl -> paired Wintun/Tuntom -> Smithproxy CONNECT -> HTTPS example.com`.
The probe reported 74 transmitted and 19 received inner packets. The Saslik
audit confirmed open, two successful heartbeats, and close; the server endpoint
unit was collected. The existing Linux tunnel remained running. This proves
the paired transport path, not GUI-driven application selection or whole-host
Windows routing. No default route was changed.
An immediate second run reused the saved Windows pairing without a new
invitation and passed the same probes and cleanup (71 transmitted, 19 received).

### Native routing-generation worker

`runServiceTunnel` composes the adapter, authenticated address setup, paired
transport and deferred native route plan under the existing guarded supervisor.
It is suitable for a `RoutingController` runner. The trusted caller supplies an
already armed capture guard and a route-plan factory, not arbitrary IPC route
expressions. The plan is constructed only after authenticated addressing and
transport health. Setup errors remain blocked until Stop. Cleanup joins the
session, withdraws routes, then destroys address ownership and the adapter;
unsuccessful route removal retains the guard and retries.

`service_tunnel_live` exercises this composition with the real paired endpoint
and `RoutingController`. Its fixed `false` capture filter deliberately blocks
nothing: this is a lifecycle fixture, **not a traffic-isolation test**. It creates
only `203.0.113.254/32` through the tunnel, never a default route. Run it through
`tests/paired-tunnel-live.ps1 -ServiceWorker -WinDivertDirectory ...` with the
usual paired-probe parameters; the script verifies Active, the owned route,
address/MTU, payload transport, Stop/Idle and cleanup. `--reject-open` appended to
the executable arguments injects a control-open failure and verifies Blocked
persists until Stop. This does not yet install the production SCM runtime or
connect the desktop's pairing handoff to that runtime.

Windows VM verification on 2026-10-28 passed Active -> Stop -> Idle, the owned
TEST-NET route, three pings and HTTPS through Smithproxy CONNECT (57 transmitted,
36 received inner packets). Default routes were unchanged and adapter/route
cleanup passed. The injected control rejection separately remained Blocked until
Stop and left no fixture adapter or route.

### Authenticated selection boundary

`authorizePipeSelection()` obtains the client's OS token from a server-side
named pipe after the request has been read, reverts impersonation immediately,
and validates the requested PID plus creation time against the process owner's
SID. It never accepts a SID or token handle from request fields. The resulting
`ProcessTarget` pins the process; it does not attach, route or launch anything.
Anonymous tokens, stale identities, wrong-side pipe handles and foreign-user
processes are rejected. The worker must enter without existing impersonation;
failure to revert terminates the process rather than processing more requests
under an unknown security context.

The live tests use a local owner/SYSTEM-only pipe with remote clients rejected
and identification-level client tokens. They cover own-process authorization,
stale/invalid/anonymous rejection and impersonation cleanup. The service lifecycle
fixture additionally verifies rejection of a LocalService-owned target from the
invoking user's pipe identity. No new user account or credential is needed.

This is the authorization primitive, not yet a deployed GUI/service protocol.
The actual endpoint still needs bounded/cancellable message handling, explicit
ACLs and remote-client rejection, protocol validation and selection lifetime
management. A SYSTEM service must retain the authenticated selection instead of
reopening it through a current-user-only observer constructor.

### Service lifecycle host (not yet the routing service)

`runService()` hosts one worker in an own-process Windows service. SCM stop and
shutdown controls signal a manual-reset event; the status owner reports stop
checkpoints while joining the worker. Worker failures become service-specific
SCM errors rather than a false clean exit. The worker must honor cancellation;
the host does not forcibly kill a stuck thread. Callback context remains alive
until process teardown, avoiding callbacks into destroyed stack data.

SCM `Running` means the worker was started, not that interception or a tunnel is
ready. A future routing service needs a separate readiness/health contract and
authenticated user-scoped IPC. Its service account and driver privileges remain
to be designed; the lifecycle test's LocalService account does not demonstrate
that LocalService can open WinDivert or impersonate the selecting user.

`tests/service-host-live.ps1` creates unique demand-start LocalService fixtures
from a binary copied beneath Program Files. It tests normal stop and worker
error 42, then removes only those services. The copied binary is retained for
audit. No production service, auto-start, recovery policy or network change is
installed, and the test is excluded from CTest.

### Worker-owned packet capture (not yet a service)

The session-zero integration fixture `capture_service_test` now connects the
service host to `PacketCapture`. Its compiled-in `false` filter intercepts no
traffic. `tests/capture-service-live.ps1` installs unique, demand-start LocalSystem
fixtures from an administrator-owned Program Files directory, verifies the
official DLL/SYS hashes and driver signature, and removes the fixture services
afterwards. It leaves binaries/status logs for audit, never removes the shared
WinDivert driver, and does not change routes or install automatic recovery.

The fixture distinguishes `starting`, `capture_ready`, `stopping`, `stopped` and
`failed` in its status log. Every state explicitly says `routing_ready=false`.
A missing DLL must fail without ever reporting capture readiness. Normal capture
shutdown and that failure path passed on the Windows development VM. This is
not authenticated status IPC or the production routing service; use of
LocalSystem here does not settle the eventual privilege-separation design.

`traffic::PacketCapture` provides reusable NETWORK capture and explicit
reinjection, independently of Qt, process selection and the tunnel. A single
worker owns it; counters need no global lock. Reads use overlapped I/O, retain
the same pending request across timeouts, and drain cancellation before freeing
buffers. Returned packets own their bytes and original WinDivert metadata.
Reinjection calculates checksums and reports successful packet/byte counts.

Cancellation is terminal for the reader and rejects subsequent reinjection, but
keeps its filter installed until destruction. The supervisor must stop/join the
worker before destroying it. Destruction closes the handle and removes that
filter; this is not persistent protection after service failure. Packet expiry
or cancellation never implicitly reinjects anything. The trusted backend builds
filters; raw filter language must not become an unprivileged GUI/IPC API.

The VM packet fixture now exercises this component, including idle timeout
reuse, in-flight cancellation, pending-read destruction and counters, alongside
TCP SYN/UDP correlation for IPv4/IPv6. It is not yet a long-running Windows
service, application-routing controller, or tunnel forwarding loop.

This directory is part of Skewer, not a separate product or GUI fork. It is a
native backend selected by the root CMake build on Windows. Both platforms use
`src/ui/application_shell.hpp` and `src/ui/application_page.hpp`: the same window
lifecycle, tray/menu, geometry, version, tabs and Applications layout. Linux
retains its cgroup controller; Windows supplies its native scanner, portable
process browser and authenticated routing-service client. Unsupported routing
coverage is explicitly described rather than silently bypassed. The former
separate preview executable has been replaced by `skewer.exe`.

Implemented:

- Current-user process enumeration using token SIDs, not account names.
- PID + creation-time identity; parent links reject newer reused PIDs.
- Executable paths, session IDs and visible top-level window titles.
- Window-bearing processes sort before background processes.
- Process launch without a command shell or handle inheritance.
- Unicode and Windows argument quoting; no administrator elevation requested.
- RAII handle ownership and runtime regression tests.

This is a process inventory, not yet application grouping. A process may vanish
during collection. Access-denied entries are counted, not shown as owned.
Window enumeration is scoped to the caller's desktop: a probe run through SSH
cannot see the interactive desktop's windows. The GUI gathers window
metadata in its own desktop session, not in a system service. The helper should
receive verified process identities, not blindly trust arbitrary PIDs.

## Build from Linux

Install CMake, Ninja and the POSIX-threaded x86-64 MinGW C++ toolchain, or use an
isolated container. No Windows SDK or proprietary compiler is required here.

```sh
cmake -S platform/windows -B /tmp/skewer-windows-build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/platform/windows/mingw-toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/skewer-windows-build
```

Run `skewer-process-probe.exe --self-test` on real Windows. Cross compilation
alone does not validate Win32 behavior. `--json` emits a diagnostic inventory;
window titles can be sensitive, so do not publish captures indiscriminately.

## Shared GUI

The programmatic widget in `platform/common` contains no operating-system APIs.
It separates window-bearing processes from background roots, retains process
ancestry, and never merges applications merely because executable names match.
Selection/expansion survive refresh; PID reuse invalidates old selection.
The shared page supplies search and routing action controls on both platforms.
Linux keeps its richer cgroup model and runtime-specific trust integrations.
Windows has native current-user CA management, managed runtime trust, and a
read-only Connections page backed by the IPv4 and IPv6 TCP/UDP IP Helper owner
tables. The connection route column is the service's current policy state, not
packet-level proof of interception.

The Windows application polls on a worker thread every three seconds by default, with no
overlapping scans and no polling while minimized. It exposes launch progress,
errors and the returned PID, and learns name/path completions from the inventory.
Visible application names take precedence over renderer/helper labels. Distinct
executable paths remain separate even when their names match. Up to 256 entries
are retained in memory for the current session, including exited applications;
this history is not written to disk. Selecting a completion inserts its actual
executable path, never its display label. The launcher accepts separate
executable and argument fields and never invokes a command shell.
It never edits browser profiles or requests elevation. Successful process
creation does not prove that a singleton application opened a new instance.
Closing the window does not terminate applications it launched. The shared
close-to-tray setting and explicit Quit behave like Linux. Reopening activates
the existing per-user window. Windows Preferences exposes only implemented
options: process refresh interval and tree font size.

To cross-build the application, install Qt target libraries and matching Linux
host tools (including ICU) and build from the repository root:

```sh
aqt install-qt windows desktop 6.8.3 win64_mingw -O /tmp/qt-target --archives qtbase qtsvg
aqt install-qt linux desktop 6.8.3 linux_gcc_64 -O /tmp/qt-host --archives qtbase icu
export LD_LIBRARY_PATH=/tmp/qt-host/6.8.3/gcc_64/lib
cmake -S . -B /tmp/skewer-windows-app-build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/platform/windows/mingw-toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/tmp/qt-target/6.8.3/mingw_64 \
  -DQT_HOST_PATH=/tmp/qt-host/6.8.3/gcc_64
cmake --build /tmp/skewer-windows-app-build
```

The result is `platform/windows/skewer.exe` in the build directory, using the
root project's version. Native Linux `rcc` compiles the shared SVG resource;
no layout editor is used. `cross.Dockerfile` supplies the isolated compiler and
host runtime dependencies. The tested build uses Debian 12 POSIX MinGW GCC 12,
Qt 6.8.3 and Qt's MinGW 13.1 runtime DLLs.

For the private test directory, deploy the executable alongside `Qt6Core.dll`,
`Qt6Gui.dll`, `Qt6Widgets.dll`, `Qt6Concurrent.dll`, `Qt6Network.dll`, `Qt6Svg.dll`, matching `libstdc++-6.dll`,
`libgcc_s_seh-1.dll`, `libwinpthread-1.dll`, and the cross-compiler's
`libssp-0.dll`. Include `platforms/qwindows.dll` and
`styles/qmodernwindowsstyle.dll`, `iconengines/qsvgicon.dll` and
`imageformats/qsvg.dll` from Qt. This is a development deployment,
not a signed installer or a complete redistribution/license bundle.

## Tests

The portable model suite runs without Linux services:

```sh
cmake -S platform/common -B /tmp/skewer-portable-ui
cmake --build /tmp/skewer-portable-ui
ctest --test-dir /tmp/skewer-portable-ui --output-on-failure
```

The Windows build also produces tests under `platform/windows/portable-ui`.
Run it on Windows with `QT_QPA_PLATFORM=offscreen`, `Qt6Test.dll` and
`platforms/qoffscreen.dll`. It checks the Qt model contract, distinct instances,
parent cycles, reused PIDs, refresh state, search and launcher suggestions.
`application_shell_test.exe` covers shared tabs, disabled action defaults,
version, preferences hook, resizing and geometry persistence.
`launch_catalog_test.exe` covers name/path matching, keyboard selection, distinct
installations, stable refresh and bounded session-only history.

`tests/application_smoke.ps1` must run in an interactive desktop session with
Skewer already open. It launches Notepad, checks error/success feedback,
single-instance activation, close and reopen, and verifies Notepad remains running. Use only a disposable
development VM; it intentionally leaves the test application running.
Results are written to the user's `skewer-application-smoke.log`.

Native validation on 2026-10-26: MinGW cross-build succeeded; Windows 11
Enterprise Evaluation on RHINO passed the self-test in an unelevated desktop
session, including visible/hidden window association. SSH passed the remaining
tests and explicitly skipped desktop tests. JSON parsing with PowerShell passed.
`windowEnumerationAvailable` distinguishes a noninteractive window station
from an interactive desktop with no matching windows. This is not yet coverage
of multi-user isolation, application grouping or networking.

The portable Qt model and shared-shell suites passed on both Linux and Windows.
Linux's existing application-model and Saslik-status integration tests also
passed after adopting the shared shell and page. The desktop
launcher/close smoke test passed on Windows; the application rendered with the
native Qt Windows style. No routing or full functional parity is claimed.

## Next milestones

### Wintun OS boundary (experimental, not connected to routing)

`wintun_device` provides RAII adapter/session ownership, nonblocking packet I/O,
backpressure and cancellable waits. It uses the official Wintun SDK dynamically;
the library remains loaded until its last device is destroyed. Reads release
their ring slots even when the caller's buffer is too small. The Wintun read
event is borrowed and is never closed by Skewer. Stop and join all I/O workers
before destroying a device.

This library does **not** yet port the Tuntom transport, install a kill switch,
assign IP addresses, configure DNS or change routes. It is deliberately not
linked into the GUI. No production Windows routing is enabled by this step.

Obtain the official Wintun 0.14.1 SDK from
[wintun.net](https://www.wintun.net/). The archive SHA-256 is
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Keep the SDK's license with the DLL; this repository does not redistribute it.
Add these options to the Windows cross-build configuration (paths must be
visible inside the build environment):

```sh
-DSKEWER_WINDOWS_TUN=ON -DWINTUN_INCLUDE_DIR=/path/to/wintun/include
```

`wintun_device_test.exe` runs deterministic tests with an injected API and no
driver or elevation. The explicit live probe requires administrator rights and
creates a uniquely named test adapter, then closes it:

```powershell
.\wintun_device_test.exe --live C:\TrustedInstall\wintun.dll
```

Run the live probe only in the development VM. Verify the DLL's Authenticode
signature first; the loader restricts search paths but does not authenticate the
binary itself. A future privileged service must use an administrator-controlled
installation path, never a DLL path supplied by an untrusted GUI request. Closing
the probe removes its adapter but does not uninstall the shared Wintun driver.

### UDP transport foundation

`skewer-windows-udp` provides nonblocking Winsock datagrams for numeric IPv4
and IPv6 endpoints. It owns Winsock/socket/event lifetime, prevents inherited
socket handles and duplicate local binds, preserves source addresses, and treats
truncation as an error. Empty datagrams are distinct from an empty receive queue.
There is no implicit DNS lookup, peer migration, authentication or route setup.

The wait operation combines cancellation, network events and an optional borrowed
packet-device event. Stop wins over simultaneous readiness. Network readiness is
advisory (including write readiness); callers must handle would-block and use
bounded receive batches so other work is not starved. Socket events are reset
atomically using Winsock's event enumeration, not `ResetEvent`. One I/O worker
owns the endpoint; stop and join it before destruction. A future Wintun supervisor
must keep any borrowed packet-device event alive throughout each wait.

`udp_endpoint_test.exe` needs neither elevation nor a driver. It uses IPv4 and
IPv6 loopback to test packet/reply integrity, empty/truncated/oversized datagrams,
readiness, cancellation priority, duplicate binds and handle cleanup. It does
not alter addresses or routes. Scoped IPv6 address parsing, PMTU policy, socket
buffer tuning and the actual Tuntom protocol integration remain separate work.

### Shared Tuntom session core

Pass `-DTUNTOM_SOURCE_DIR=/path/to/tuntom` to consume the actual Tuntom headers
through `skewer-tuntom-session`. The checkout must include the portable
`packet_types.hpp`, `protocol_constants.hpp` and `info_codec.hpp` split. No
download or source modification happens during configuration. The GUI does not
yet link this target. Windows session entropy uses CNG (`bcrypt`); the wire
codec, handshake, PFS, encryption and replay protection remain Tuntom code.
The first verified Tuntom revision is `bb5401e` (portable session core).

`tuntom_udp_test.exe` exercises the shared client and server session implementations
over real Winsock IPv4/IPv6 loopback datagrams. It verifies the four-message PFS
handshake, encrypted traffic in both directions, tamper/replay rejection and
wrong-PSK rejection. This is not yet a Windows-to-Linux interoperability test or
a Wintun-to-remote-host tunnel test. No production key or network route is used.

### Experimental packet pump

`skewer-tunnel-pump` connects a `PacketDevice` (implemented by `WintunDevice`)
to the shared session and a fixed UDP peer. A single worker handles bounded
16-packet batches, handshake/rekey timers, authenticated PING/PONG probes and a
five-second receive-health deadline. Cancellation and errors invalidate health.
The worker borrows its device, socket and stop event; stop/join it before
destroying them. Run one pump per session, never call `step` concurrently with
`run` or inspect counters concurrently without owner-side synchronization.

This initial transport has a fixed **1280-byte inner MTU**. The future adapter
setup must configure that MTU before routing traffic to it. Larger outbound
packets are counted/dropped, not fragmented or silently queued. Inbound fragments
use Tuntom's bounded reassembly. UDP/device backpressure drops packets and is
counted; there is no pending data queue to survive key changes or reconnects.
Only the configured address/port is accepted, with IP header length checks before
device injection. VPN AUTH/config extensions are explicitly unsupported and
terminate the worker; this is a fixed-peer PSK transport only.

`tunnel_pump_test.exe` uses real IPv4/IPv6 loopback UDP and an in-memory packet
device. It tests inner IPv4/IPv6 transfer, unconfirmed/stale-session drops,
foreign peers, MTU/invalid headers, full device rings, session recovery and stop.
An idle-peer regression answers only probes (no unsolicited keepalives), then
stops answering to verify that the receive-health deadline still closes.
Wintun driver I/O is separately covered by `wintun_device_test`.

The explicit elevated VM-only probe `tunnel_pump_live.exe` exercises the combined
pump with the real Windows IP stack and Wintun driver. Run the repository's
`platform/windows/tests/tunnel-pump-live.ps1 -Directory C:\\TrustedTestDirectory`
with the executable and signed `wintun.dll` in that directory. It creates a
uniquely named adapter, assigns only `198.18.254.1/30` in ActiveStore, sets MTU
1280, waits for address readiness and requires three successful pings to
`198.18.254.2`. The remote endpoint is a narrow in-process ICMP responder reached
through encrypted loopback UDP, not an actual Saslik server. Both session peers
use an ephemeral random key. The probe times out after 45 seconds and adapter
destruction removes its test configuration. The script verifies adapter/route
cleanup and unchanged IPv4/IPv6 default routes, retaining per-run logs.

This probe is deliberately excluded from CTest, never installs a default route
or changes host firewall policy, and must not run on a production host. It proves
kernel-to-Wintun-to-session-to-UDP-to-echo and return-path integration only, not
TCP/UDP application behavior or leak protection.

For actual Linux interoperability, add `-RemotePeer <numeric IPv4>` to the
PowerShell script and supply a disposable 32-hex `TUNTOM_SECRET` in its
environment. This selects tunnel ID 242, UDP port 40242, and disables the local
echo session. Prepare a real Linux Tuntom server with inner MTU 1280, default
encrypted/PFS mode and PMTUD disabled. Its TUN must have `198.18.254.2/30` inside
an isolated network namespace, with no forwarding or Internet route. Restrict
the test UDP port to the Windows VM and bound the server lifetime; remove the
test namespace and firewall rule afterwards. Never reuse a deployment key.
The script waits seven idle seconds before pinging, exercising liveness beyond
the five-second health deadline. Keys are not placed in process arguments.

Validated on the development Windows VM against the Linux Tuntom daemon on
RHINO: real Wintun -> encrypted UDP -> Linux TUN -> kernel ICMP echo replies.
This remote test covers inner IPv4; live IPv6 and application interception are
not yet validated.

Add `-HttpProbe` to also run Windows `curl.exe`, explicitly bound to the test
address with proxy use disabled, against `http://198.18.254.2:18080/`. The script
requires the exact fixture response before running ICMP and checking cleanup.
This is actual application TCP over Wintun/UDP to Linux, not per-process
WinDivert selection or a Saslik proxy/internet test.

For an isolated RHINO fixture, place `tests/remote-http-peer.sh` and
`tests/remote-http-endpoint.py` together on that host and provide the Linux
Tuntom binary at `/tmp/tuntom-interop-linux`. Run the shell script as root;
it creates a separate namespace with no default route, binds the HTTP listener
inside it, restricts UDP 40242 to the test VM and cleans up after 90 seconds.
Its public disposable PSK is `73737373737373737373737373737373`; supply the same
value as the Windows test's `TUNTOM_SECRET`, never for a deployed endpoint.
The fixture assumes VM address 192.168.199.131 on virbr0. Do not reuse it on a
different network without reviewing those restrictions. Synchronize guest and
host clocks first: the protocol rejects excessive clock skew, as it should.

Remaining integration includes adapter addressing/routes, outbound fragmentation
and PMTU, leases, VPN AUTH/config, supervisor/GUI integration and independently
enforced Windows fail-closed policy. The GUI does not enable this transport.
Protocol/pump health alone must never be exposed as proof of protected application
connectivity, and the pump itself is not a kernel kill switch.

### Reusable application traffic policy (experimental)

`ProcessTarget` is the transport-independent reference used to validate a
selected process instance. It opens a non-inheritable query/synchronize handle,
checks the snapshot's PID and creation time, verifies current-user ownership,
and records the executable path. A stale or exited selection fails rather than
silently adopting the current occupant of a PID. The borrowed wait handle lets
an event-driven supervisor observe exit without a high-frequency process scan.
Destroying this reference closes only its handle, never the application.

This is a current-user API, not yet a privileged service authorization boundary.
A future service must obtain the requesting identity from authenticated IPC,
not trust a SID/PID supplied by the GUI. `running()` is a point-in-time check;
holding a process handle does not freeze execution or prevent a subsequent exit.
It also does not label packets or convert an image-based WFP filter into a
per-instance filter. The process self-test covers two instances of the same EXE,
stale creation timestamps, mismatched handle/PID pairs, non-inheritance, handle
cleanup and exit code `STILL_ACTIVE`. It does not force real OS PID reuse.

Application selection, enforcement, interception and traffic consumption are
separate responsibilities. The policy library must not depend on Qt, Saslik,
Tuntom, Wintun or a remote endpoint. A future interceptor may feed a tunnel,
another forwarding backend or an observation consumer; it must not implicitly
remove the guard when that consumer disconnects. Readiness and explicit Release
belong to the policy owner, not the packet consumer's destructor.

The first implemented primitive is `traffic::AppImageBlock` in the independent
`skewer-app-egress-guard` library. It blocks new outbound ALE authorizations for
an absolute executable path, across **all instances and users of that image**.
It does not pretend that an image identity is a process-instance identity.
No PID selection, child tracking, packet diversion or tunnel exception exists
in this primitive. The GUI does not use it.

The caller supplies and persists a unique policy GUID. Both address-family
filters and their private sublayer are installed in one WFP transaction with
persistent lifetime. Closing the engine or destroying the C++ object does not
release them. `release()` is explicit and verifies the stored image identity
and filter shape before deleting only that policy's objects, transactionally.
An incomplete or conflicting policy fails visibly, not as a successful attach.
Administrative access is required; this is not an authenticated IPC service.

Run `platform/windows/tests/app-egress-guard-live.ps1 -Directory <test directory>`
only in the elevated development VM, with `app_egress_guard_test.exe` present.
The script creates two uniquely named copies of the fixture, checks loopback
IPv4/IPv6 TCP and UDP, arms only one copy, forcibly terminates its policy owner,
checks TCP `WSAEACCES` and UDP nondelivery for the selected copy, verifies the other
copy is unaffected, and explicitly releases the policy in `finally`.
It also checks idempotent arm and rejection of release by a different image.
No browser, SSH service, host default route or production application is touched.
Logs and fixture copies remain for inspection. If cleanup fails, the script
prints the exact release command; retain that executable until cleanup succeeds.
The live policy test is intentionally excluded from unattended CTest runs.

This is **not yet the per-instance fail-closed backend**. Remaining acceptance
includes physical egress capture, existing connections, shared DNS, spawned
children, instance identity/PID reuse, interface exceptions, restart/lease
behavior, and reboot/early-boot coverage. A successful `installed()` reports
the filter definitions, not end-to-end protection against every bypass.

WFP references: [object lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
[ALE authorization layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers).
Older MinGW headers omit the three standard GUIDs and persistence flag used
here; their local ABI constants match Microsoft's
[SDK metadata](https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders).

### Passive per-instance flow observation

`skewer-flow-observer` is an optional native library, independent of Qt and
Tuntom. Enable `SKEWER_WINDOWS_FLOW=ON` and set `WINDIVERT_INCLUDE_DIR` to the
official WinDivert SDK's `include` directory. No SDK binary is vendored or
automatically downloaded. The DLL is loaded from an explicit trusted absolute
local path; its installation directory must not be writable by untrusted users
when a privileged caller loads it.

The observer pins an existing current-user `ProcessTarget` (PID plus creation
time), opens a numeric PID filter at WinDivert's read-only, sniffing FLOW layer,
and returns TCP/UDP establishment/deletion metadata for IPv4 and IPv6. It waits
on overlapped I/O, cancellation and process exit, without a polling loop. A
timeout keeps the read pending; cancellation/destruction drains that request
before its storage is freed. Cancellation or target exit permanently retires
the observer. It does not terminate or move the selected application.

Only future flows are observed. Existing sockets, child processes and shared
resolver traffic are not implicitly included. Events can be lost under load;
these observations must **not** authorize traffic or provide a kill switch.
This phase neither diverts packets nor integrates the observer into the GUI.

`TrackedFlowObserver` now combines those events with the portable flow index.
IPv4/IPv6 endpoint text is normalized into network-order bytes using InetPton,
with family mismatches and malformed input rejected. Cancellation, process exit
or a read failure invalidates retained correlation; lookup also checks the pinned
process handle before returning a result. The wrapper never resets a lost epoch
automatically. Index capacity/expiration limits remain visible as `Unreliable`.
This observer sees only its selected PID: absence of another owner is **not**
proof that no unobserved process shares the tuple. No ownership authorization or
live packet interception is inferred from these diagnostic matches.

For manual diagnostics, the same opt-in build provides a console command:

```powershell
.\skewer-flow-watch.exe 1234 C:\SkewerDev\flow-test\WinDivert.dll
```

Run it elevated as the same user as the target. It prints OPEN/CLOSE events to
stdout and readiness/termination messages to stderr. IPv6 endpoints are bracketed;
each record contains the pinned PID, creation time and endpoint ID, plus
`correlation=observed|unknown|ambiguous|unreliable` after applying that event.
This is the event's tuple lookup, not a claim that a captured packet was matched.
Ctrl+C or
Ctrl+Break cancels observation without stopping the application. Target exit
ends observation; the command never switches to a new process reusing its PID.
Redirected output can contain sensitive network endpoints: retain it accordingly.
This is a diagnostic console, not a privileged IPC service or production installer.
`--self-test` validates arguments without loading a DLL or requiring elevation.

The opt-in `tests/flow-observer-live.ps1` runs `flow_observer_test.exe` in an
elevated disposable Windows VM. Put the official **2.2.2-A x64** DLL, SYS and
LICENSE next to the executable. The script verifies pinned DLL/SYS SHA-256
hashes and a valid driver signature before running. First open may install the
driver; never disable driver-signature checks or antivirus to make it work.
The test checks two instances of the same image, loopback TCP/UDP IPv4/IPv6,
event decoding, timeout continuation, cancellation, target exit and pending-I/O
destruction, plus the `skewer-flow-watch.exe` command against a synchronized
fixture. Put that executable and `flow_tracking_test.exe` in the test directory
too; normalization tests run without loading the driver. The live tests are
excluded from unattended CTest. Closing the handles removes
their filters; the script deliberately does not delete the shared driver service.

Use the official [WinDivert 2.2.2 release](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)
and retain its LICENSE when distributing its files (LGPLv3/GPLv2 dual license).
See the [FLOW API documentation](https://github.com/basil00/WinDivert/blob/v2.2.2/doc/windivert.html).

### Selection request framing

`selection_request.hpp` defines a strict 20-byte, little-endian request:
`SKWR` (4 bytes), version `1` (u16), operation `1` (u16: validate selection),
PID (u32), process creation time (u64, Windows FILETIME units). Both identity
fields must be nonzero. Unknown headers, truncated messages and trailing bytes
are rejected. Encoding is explicit and independent of native structure padding.

The named-pipe authorization fixture now transmits and decodes this message
before checking the OS client token. This is **not** a routing command or a
deployed GUI/service protocol yet. A production server must enforce message
boundaries (including rejecting `ERROR_MORE_DATA`), bounded/cancellable I/O,
an explicit local ACL and server authentication. Never trust a request-provided
user identity. Persistent selection ownership and production transport remain pending.

The reply is exactly 8 bytes: `SKWA`, version `1` (u16), status (u8),
reserved zero (u8). Status is `0` verified, `1` invalid request, or `2` denied.
Unknown statuses and malformed replies are rejected. A verified reply is never
a claim that routing is enabled. Use one outstanding request per connection;
there is no multiplexing or request ID in version 1.

`processSelectionRequest` validates an already-read message and authenticates
the pipe client, returning both the reply and the pinned target on success.
Stale, inaccessible and foreign targets share the denied response; internal
programming errors propagate. The caller must retain the target, not reopen its
PID as SYSTEM, and recheck liveness when using it. This dispatcher performs no
I/O or policy changes. The VM fixture tests the request/reply round trip.

`serveSelection` adds one bounded exchange on an already-connected overlapped,
message-mode server pipe. Read and write share a 1..60000 ms budget and a
manual-reset cancellation event. Pending I/O is cancelled and drained before
buffers are released. Oversized messages fail the connection; short messages
receive an invalid-request reply. The caller must close/disconnect on failure.
No blocking `FlushFileBuffers` is used. The budget bounds I/O waits, not the
synchronous OS process/token queries or kernel cancellation completion.

`createSelectionPipe` creates an exclusive local message endpoint with a
protected DACL: SYSTEM has full access and the user from a trusted setup token
has specific read/write rights, excluding creation of another pipe instance.
Clients request `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
FILE_WRITE_EA`, not `GENERIC_WRITE` (which includes instance creation rights).
Names accept only a short alphanumeric/dash/underscore suffix. Remote clients
are rejected. The service must obtain the setup token from trusted session
configuration, never from a request. First-instance protection does not replace
server authentication: a squatter can still preoccupy an unused name.

`acceptSelection` waits with a bounded timeout and cancellation, draining pending
connect I/O on failure. Keep the endpoint handle alive for its lifetime and
disconnect failed clients before reusing it. Tests cover exclusive creation,
invalid names, idle accept timeout, pre-set cancellation, ACL-compatible client
connection and authenticated request/reply, plus short/oversized messages.
This is still a library, not a deployed service: the SCM worker loop, server
authentication by the GUI and persistent selection management remain pending.

Client-side `verifySelectionServer` checks the connected pipe's server PID,
creation time and liveness and returns a retained process handle.
`verifySelectionService` obtains the expected PID from the locally installed,
running own-process service, pins that process, verifies the pipe and rechecks
SCM. The service name must be trusted application configuration; service
installation and executable permissions are part of this trust boundary.
This does not defend against an administrator replacing the service.
Call verification before sending any request and retain the handle throughout
the exchange. Never reconnect silently after verification.

VM tests currently cover a valid pinned local server and rejection of wrong
PID, stale creation time, the wrong pipe endpoint and a missing service.
GUI integration remains untested and is not enabled. The separate SCM fixture
below verifies the worker/client path without the GUI.

`tests/selection-service-live.ps1` now exercises a real temporary SCM worker
and authenticated client twice, then verifies clean service stop. It copies the
fixture under Program Files and removes only its own uniquely named service.
The fixture runs as LocalSystem solely to read the trusted launcher's token;
the launcher's PID and creation time are administrator-provided service arguments,
not IPC input. Production session discovery is not implemented by this fixture.
`exchangeSelection` verifies SCM before transmitting and retains the server
process through the bounded exchange. `finishSelection` waits briefly for peer
close before disconnecting, avoiding lost buffered replies without blocking
indefinitely in `FlushFileBuffers`. These paths are VM-tested; GUI integration
and persistent routing selections remain pending. No routing policy is installed.

### Remaining first-release limits

The native service and GUI now cover authenticated pairing, whole-host IPv4 and
selected-process IPv4 TCP/UDP routing. Unsupported IPv6, already-open sockets,
orphaned handoffs and ambiguous shared UDP binds remain explicit limitations;
they are never presented as successfully routed. The first release uses the
documented WinDivert owner-lifetime model rather than the deferred custom driver.
Skewer application executables are not yet code-signed; the packaged Wintun and
WinDivert drivers retain their official signatures.

The Linux executable keeps its cgroup backend. The shared shell and portable UI
models preserve common layout and behavior, while each platform supplies native
process discovery, trust and routing controllers. GitHub Actions cross-builds a
versioned Windows ZIP from pinned inputs, verifies it on a native Windows runner,
and publishes it only after the Linux and Windows gates pass.

### Versioned Windows ZIP

`packaging/package-windows.sh` assembles the application, independent routing
service, control client, official signed Wintun/WinDivert artifacts, Qt/MinGW
runtime, installer scripts and dependency notices into
`skewer-windows-amd64-VERSION.zip`. It accepts an existing cross-build and SDK
roots; it does not download or silently substitute dependencies. The companion
PowerShell verifier checks the complete runtime, pinned WinDivert hashes, driver
signatures, all three production executables and executable version on Windows
before publication. `test-windows-package.ps1` additionally exercises isolated
per-user install, execution and uninstall without touching pairing, preferences
or the independently installed routing service.

### Verified selection handoff

The flow observer and tracked observer accept ownership of a `ProcessTarget`
already authenticated at the IPC boundary. The service can move
`SelectionResult::target` directly into the observer without reopening its PID
or comparing the user against SYSTEM. The same pinned handle supplies identity
and exit notification for the observer lifetime. The tracked layer no longer
opens a second copy of the process. The current-user convenience constructor
remains available to diagnostics. Missing/dead selections are rejected before
loading WinDivert; correlation remains diagnostic, not packet authorization.
