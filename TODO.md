# Skewer roadmap

## Windows first release: WinDivert lab routing

WinDivert is the selected interception backend. A custom WFP kernel driver is
not a first-release dependency. Windows routing is still under development;
these items are acceptance gates, not implemented capabilities.

- [ ] Run interception in a privileged service independent of the GUI, with
  authenticated local IPC and verified current-user process identities.
- [ ] Establish interception before admitting selected traffic; bound queues and
  handle unknown ownership explicitly. A late FLOW event cannot protect the
  first packet by itself.
- [ ] Integrate diversion and return traffic with Wintun/Tuntom; exclude the
  service and tunnel control traffic from interception.
- [ ] Keep selected traffic blocked during tunnel loss while the service lives;
  verify readiness before resuming forwarding.
- [ ] Test physical egress for TCP/UDP and IPv4/IPv6, initial packets, existing
  sockets, descendants, shared DNS, reconnect and GUI restart. Reject unsupported
  cases visibly rather than claiming they are routed.
- [ ] Report service failure accurately. Test and document that owner termination
  removes WinDivert filters and may restore direct connectivity. Automatic restart
  improves availability but cannot guarantee leak-free recovery.
- [ ] Package official signed dependencies and licenses. Do not require
  test-signing or disabling Secure Boot on users' machines.

Skewer is a laboratory/testing tool, not a security isolation boundary. See
[the Windows contract](platform/windows/TUNNEL_PARITY.md).

### Deferred: custom kernel guard

Keep the build-only `platform/windows/driver` prototype for possible later work.
Do not load, package or require it for the first release. Revisit only if strict
per-instance protection surviving service failure becomes a product requirement.

## Target: whole-host routing through Saslik

Whole-host routing is an explicit alternative to application selection, for both
Linux and Windows. It is not enabled yet and does not implicitly include traffic
forwarded from VMs, bridges or other machines.

The initial portable `routing_scope.hpp` admission model is unit-tested but not
wired into IPC, UI or route mutation. It keeps empty application selection inert,
requires separate backend capability and authorization for whole-host scope,
and rejects invalid enum values. This does not complete the activation checklist.

- [ ] Expose routing scope (selected applications / whole host) independently
  from transport (direct next hop / Tuntom). Require explicit privileged consent
  for whole-host activation; never infer it from an empty application selection.
- [ ] Support direct routing through a reachable Saslik gateway and tunnelled
  routing to a remote Saslik. Validate the return path before reporting ready.
- [ ] Before redirecting host traffic, preserve the tunnel peer's underlay path
  using the original gateway/interface. Exempt only required transport/control
  traffic; do not blanket-exempt every application talking to the peer address.
- [ ] Handle endpoint changes, DNS bootstrap and physical interface/gateway
  changes without recursively sending tunnel traffic into its own adapter.
  Install and verify the replacement underlay path before retiring the old one.
- [ ] Define visible local-network and infrastructure exemptions (loopback,
  DHCP, IPv6 neighbour discovery, control plane); do not silently exempt all
  private networks. Route normal DNS through the chosen path.
- [ ] Cover IPv4 and IPv6. Unsupported families/protocols must be explicitly
  blocked or rejected, never silently bypass a claimed whole-host mode.
- [ ] Keep host data traffic blocked during tunnel loss while the worker lives;
  permit only the bounded recovery/control paths. No automatic direct fallback.
- [ ] Make activation, scope switching and rollback transactional. Remove only
  Skewer-owned changes, preserving concurrent DHCP, VPN and administrator updates.
- [ ] Distinguish pause/block from explicit Release host, which intentionally
  restores normal routing. GUI closure must do neither. Document worker-crash
  behavior separately; no stronger guarantees than the tested backend provides.
- [ ] Test real egress, peer relocation, DHCP renewal, reconnect, return traffic,
  DNS and coexistence with another VPN in an isolated VM with console access.

This is a target capability, not permission to change the development host's
default routes. Initial implementation tests use isolated VMs and rollback.

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
