# Skewer roadmap

## Windows first release: WinDivert lab routing

WinDivert is the selected interception backend. A custom WFP kernel driver is
not a first-release dependency. Windows IPv4 routing is implemented and has
passed the native VM cases listed below; unchecked items remain release gates.

- [ ] Implement selected-application **direct next-hop** for the first release
  (explicit user requirement). This is not a deferrable parity enhancement. Windows
  application selection currently uses Tuntom; Direct applies to whole-host
  routing only. Do not treat the completed whole-host Direct item below as
  evidence for per-application Direct. WinDivert 2.2 ignores outbound injection
  interface indices, so changing `IfIdx` is not a next-hop implementation.
  See the architecture constraint in `platform/windows/TUNNEL_PARITY.md`.
  Acceptance must demonstrate selected TCP and UDP reaching the configured
  gateway while an unrelated application reaches the same destination through
  its original route. Verify replies, loss protection, Release, and GUI closure;
  a successful selected request alone cannot establish routing isolation.
  An Npcap link-layer prototype is awaiting an architectural decision: do not
  install or redistribute another driver merely to satisfy this release gate.

- [ ] Diagnose intermittent client pipe setup failure (`Cannot configure routing
  pipe message mode`) observed during the selected-service IPv6 fixture on
  2026-10-29. The service remained Idle and fixture cleanup completed. Preserve
  the Win32 error in diagnostics and reproduce the disconnect/re-accept boundary;
  a successful repeat alone does not close this reliability finding. Never retry
  a potentially delivered routing mutation as a generic transport workaround.
  A deterministic native setup test now reproduces Win32 233 when the server
  disconnects after client open but before message-mode setup. The client retries
  only broken/disconnected setup handles within its original connection budget,
  before authentication or any request bytes. Invalid handles and other errors
  remain fatal. The original observation lacked its Win32 code, so this specific
  race is covered without claiming every historical IPC failure is explained.
  The native setup/authentication suite and four concurrent clients performing
  100 authenticated status reads each passed with the revised client; the full
  Windows cross-build passed as well. No routing mutation is retried by this fix.

- [x] Repeat descendant admission integration after the startup-guard race fix. The
  2026-10-29 investigation found full connect guards briefly applied even to
  descendants of an already Active group. Active descendants now retain packet
  capture and unsupported-protocol guards without a transient connect denial.
  The SCM fixture covers eight consecutive HTTPS children without sleeps/retries;
  three consecutive full VM suites passed on 2026-10-29 (24 fresh HTTPS children,
  plus the adopted-tree probes, GUI crash recovery, independent Release and UDP).
  This is bounded regression evidence, not a long-duration reliability guarantee;
  preserve diagnostics if the previously observed immediate curl exit 7 recurs.

Transport milestones verified independently of the remaining service/UI gates:

- [x] Shared TLS-PSK pairing on Windows with user-scoped DPAPI credentials.
- [x] Lease-owned packet pump, asynchronous renewal and terminal expiry checks.
- [x] Real paired Wintun/Tuntom path to Saslik: source-bound ICMP and HTTPS
  through Smithproxy CONNECT, preserving host default routes and cleaning up
  both endpoints. The same transport is now owned by the routing service for
  whole-host IPv4 and selected-process corroborated IPv4 TCP/UDP modes.

- [x] Run interception in a privileged service independent of the GUI, with
  authenticated local IPC and verified current-user process identities.
- [x] Establish interception before admitting selected traffic; bound queues and
  handle unknown ownership explicitly. A late FLOW event cannot protect the
  first packet by itself.
- [x] Integrate diversion and return traffic with Wintun/Tuntom; exclude the
  service and tunnel control traffic from interception.
- [x] Keep selected traffic blocked during tunnel loss while the service lives;
  verify readiness before resuming forwarding.
- [x] Retry selected-process and whole-host transport with bounded backoff while
  retaining interception. Publish Active only after a fresh healthy generation.
- [ ] Complete physical-egress coverage for IPv6 blocking, orphaned handoffs
  and ambiguous/shared UDP binds. Native VM tests now cover selected-root,
  new-descendant and adopted pre-existing-descendant IPv4 TCP/HTTPS; uniquely
  bound root/descendant and pre-Attach UDP/DNS; pre-Attach IPv4 TCP reset;
  pre-Attach IPv6 loopback TCP blocking with explicit-Release recovery; initial suspended
  launch; reconnect; GUI restart; whole-host DNS/HTTP/HTTPS; and tunnel-loss
  blocking. Unsupported cases must remain visibly rejected rather than being
  presented as routed.
  External link-local and on-link ULA IPv6 TCP are also verified across the VM NIC: a selected
  descendant cannot connect, an unrelated process still can, and the released
  application reconnects. A pre-existing external ULA TCP connection also passes
  peer-side no-delivery checks while selected and resumes on the same socket
  after Release. External shared UDP now also has peer-side delivery coverage:
  two pre-Attach binds and one fresh same-process bind remain blocked until
  Release. Routed ULA IPv6 also passed through a separate forwarding namespace:
  selected descendant blocked, unrelated process connected, and Release restored
  connectivity. The fixture verifies an explicit /128 route and next hop.
  Public/global IPv6 and orphaned handoffs remain coverage requirements.
- [x] Fix whole-host DNS preference against a physical NIC at interface metric 1.
  Wintun's automatic metric 5 lost DNS preference. The owned tunnel now uses
  explicit metric 0 with native read-back validation; physical NICs are untouched.
  Three cold-cache HTTPS requests, subsequent two-NIC failover and route/DNS
  cleanup passed on 2026-10-29 with the competing physical metric still 1.
- [x] Report service failure accurately. Test and document that owner termination
  removes WinDivert filters and may restore direct connectivity. Automatic restart
  improves availability but cannot guarantee leak-free recovery.
- [x] Package official signed dependencies and licenses. Do not require
  test-signing or disabling Secure Boot on users' machines.

Skewer is a laboratory/testing tool, not a security isolation boundary. See
[the Windows contract](platform/windows/TUNNEL_PARITY.md).

### Deferred: custom kernel guard

Keep the build-only `platform/windows/driver` prototype for possible later work.
Do not load, package or require it for the first release. Revisit only if strict
per-instance protection surviving service failure becomes a product requirement.

## Target: whole-host routing through Saslik

Whole-host routing is an explicit alternative to application selection, for both
Linux and Windows. Both platforms implement local-host IPv4 routing with explicit
IPv6 blocking. The Windows SCM service, authenticated IPC, GUI state restoration,
route/DNS mutation, loss blocking and cleanup passed native VM integration on
2026-10-28. Whole-host scope does not implicitly include traffic forwarded from
VMs, bridges or other machines.

The portable `routing_scope.hpp` admission model is wired into the privileged
workers and UI. It keeps empty application selection inert, requires separate
backend capability and authorization for whole-host scope, and rejects invalid
enum values. Windows now reports the authoritative scope and transport in its
versioned service protocol. The unchecked items below describe remaining
cross-platform parity and release coverage, not absence of the implemented IPv4
modes.

- [x] Expose routing scope (selected applications / whole host) independently
  from transport (direct next hop / Tuntom). Require explicit privileged consent
  for whole-host activation; never infer it from an empty application selection.
- [x] Support direct routing through a reachable Saslik gateway and tunnelled
  routing to a remote Saslik. Validate the return path before reporting ready.
- [x] Before redirecting host traffic, preserve the tunnel peer's underlay path
  using the original gateway/interface. Exempt only required transport/control
  traffic; do not blanket-exempt every application talking to the peer address.
- [x] On protected retries, rediscover the physical interface and gateway and
  install the replacement peer pin without recursively selecting the tunnel.
  Keep the existing guard armed while old owned routes are withdrawn.
- [x] Resolve a hostname endpoint before elevated installation or upgrade and
  pin one deterministic numeric IPv4 peer in the service configuration. Do not
  add a normal host-DNS bypass to the active routing guard.
- [ ] Handle endpoint/peer relocation while protection is active as an explicit
  control-plane transaction.
- [ ] Define visible local-network and infrastructure exemptions (loopback,
  DHCP, IPv6 neighbour discovery, control plane); do not silently exempt all
  private networks. Route normal DNS through the chosen path.
- [ ] Cover IPv4 and IPv6. Unsupported families/protocols must be explicitly
  blocked or rejected, never silently bypass a claimed whole-host mode.
- [x] Keep host data traffic blocked during tunnel loss while the worker lives;
  permit only the bounded recovery/control paths. No automatic direct fallback.
- [ ] Make activation, scope switching and rollback transactional. Remove only
  Skewer-owned changes, preserving concurrent DHCP, VPN and administrator updates.
- [x] Distinguish pause/block from explicit Release host, which intentionally
  restores normal routing. GUI closure must do neither. Document worker-crash
  behavior separately; no stronger guarantees than the tested backend provides.
- [ ] Test real two-NIC failover, peer relocation and coexistence with another
  VPN in an isolated VM with console access. Real egress, same-interface DHCP
  renewal, reconnect, return traffic and DNS already have VM coverage.

This is a target capability, not permission to change the development host's
default routes. Initial implementation tests use isolated VMs and rollback.
## Linux whole-host routing

GUI/TUI host scope now supports direct next-hop and Tuntom routing for local
IPv4 traffic, with explicit IPv6 blocking, persistent failure protection and
host release. See README for the operating limits and namespace tests.

- [ ] Validate against a real remote Saslik/Tuntom deployment, including DHCP
  renewal, reconnect, return traffic, DNS and coexistence with another VPN.
- [ ] Support automatic peer address relocation while host routing is blocked;
  recovery currently reuses the resolved peer until Release host and reconnect.
- [ ] Add IPv6 forwarding; unsupported IPv6 currently remains blocked.

## Enterprise: interface traffic through Tuntom (deferred)

- [ ] Route selected interface/VM ingress through the authenticated Tuntom
  tunnel, including supported bridge ports.
- [ ] Tie forwarding to verified tunnel readiness: fail closed on loss and
  restore automatically after recovery, without falling back to direct routing.
- [ ] Define return-path handling and source-address visibility before
  implementation; SNAT versus routed guest subnets remains an open design choice.
- [ ] Cover tunnel restart, interface lifecycle and concurrent application
  routing with integration tests.

Reserved for the enterprise feature set. No implementation in the current scope;
the existing restriction on interface ingress through tunnels remains in place.

## Completed: minimal local routing

- [x] Keep application selection and process movement in `skewer-routed.slice`.
- [x] Add an explicit, configurable next-hop IP for traffic from that cgroup.
- [x] Install narrowly scoped packet marking and policy-routing rules.
- [x] Keep all unrelated host traffic on its existing routes.
- [x] Make setup, status and teardown idempotent and visible in both the GUI and TUI.
- [x] Document that sockets opened before an application is attached retain their
  previous routing; launching the application through Skewer is authoritative.

This phase deliberately has no tunnel protocol and no dependency on a Saslik
appliance. The next hop may initially be any directly reachable router prepared
to accept and forward the selected traffic.

## Later: tuntom transport

- Add tuntom as an optional transport between Skewer and a remote Saslik.
- Use the dynamic authenticated tunnel/client workflow rather than treating
  tuntom as a static GRE-like link.
- Integrate it when the Saslik VM/appliance lifecycle and its client-facing
  interface are ready.
- Preserve the local cgroup and policy-routing boundary so transport remains a
  replaceable backend.

This is intentionally deferred. Do not couple the first routing implementation
to tuntom, WireGuard, OpenVPN or the future Saslik VM.

## Later: Saslik connection utilities

- Let the user enter a Saslik URL and establish an explicitly trusted connection.
- Discover the remote workspace/identity and advertised service endpoints.
- Show Saslik and Smithproxy health and compatibility before routing traffic.
- [x] Download the active CA certificate and offer installation/removal in
  explicitly supported local NSS and system trust stores.
- Discover additional application trust stores locally and advertise them to
  Saslik through a future authenticated Skewer capability channel.
- Keep API credentials out of URLs and use a bootstrap/exchange flow when the
  Saslik API defines one.
