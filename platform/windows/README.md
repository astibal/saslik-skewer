# Windows backend and shared application UI

## First-release direction and limitation

The selected backend is WinDivert interception with Wintun/Tuntom transport,
owned by a privileged service independent of the GUI. Integration is still in
progress; this is not a claim that application routing is already available.
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
native backend selected by the root CMake build on Windows. Both platforms
use `src/ui/application_shell.hpp` and `src/ui/application_page.hpp`: the same
window lifecycle, tray/menu, geometry, version, tabs and Applications layout.
Linux retains its existing controllers and application model; Windows supplies
its native scanner and the portable process browser. There is no Windows
routing implementation yet, and unsupported operations are explicitly disabled.
The former separate preview executable has been replaced by `skewer.exe`.

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
Linux keeps its richer model, CA/connection handling and routing controllers.
Windows shows explanatory pages for CA Trust, Runtime Trust and Connections;
these are capability notices, not implemented backends.

The Windows application polls on a worker thread every three seconds by default, with no
overlapping scans and no polling while minimized. It exposes launch progress,
errors and the returned PID, and learns name/path completions from the inventory.
Visible application names take precedence over renderer/helper labels. Distinct
executable paths remain separate even when their names match. Up to 256 entries
are retained in memory for the current session, including exited applications;
this history is not written to disk. Selecting a completion inserts its actual
executable path, never its display label. The initial launcher accepts an
executable path only, not arguments.
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
not yet validated. It does not configure the Linux server automatically.

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

### Remaining integration

The independent [`platform/traffic`](../traffic/README.md) module now decodes
bounded IPv4/IPv6 TCP/UDP packet tuples. Its flow index consumes live FLOW events,
but packet capture and authorization are not yet wired; unrecognized packets cannot safely be
assigned to an application merely from FLOW events.

1. Port additional controllers behind explicit platform capability interfaces;
   do not expose Linux-specific helpers or settings as working Windows features.
2. Add desktop application identity/icons, launcher completion, and explicit
   launch feedback (new process vs singleton handoff).
3. Implement and test a separate Windows traffic-policy backend. Until then,
   attach/routing controls must be unavailable, never report simulated success.
4. Add a Windows CI runner and versioned ZIP/installer release artifacts.

The Linux executable uses the shared shell/page with its existing controllers.
Existing Linux release packaging is unchanged; Windows packaging is not ready.

### Verified selection handoff

The flow observer and tracked observer accept ownership of a `ProcessTarget`
already authenticated at the IPC boundary. The service can move
`SelectionResult::target` directly into the observer without reopening its PID
or comparing the user against SYSTEM. The same pinned handle supplies identity
and exit notification for the observer lifetime. The tracked layer no longer
opens a second copy of the process. The current-user convenience constructor
remains available to diagnostics. Missing/dead selections are rejected before
loading WinDivert; correlation remains diagnostic, not packet authorization.
