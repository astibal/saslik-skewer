# Skewer roadmap

## Linux whole-host routing

GUI/TUI host scope now supports direct next-hop and Tuntom routing for local
IPv4 traffic, with explicit IPv6 blocking, persistent failure protection and
host release. See README for the operating limits and namespace tests.

- [x] Whole Host real-world operation confirmed by the user.
- [ ] Validate the system resolver and uncached DNS after a real tunnel reconnect;
  packet-level loss/recovery is covered by the namespace regression.
- [ ] Record focused DHCP-renewal and concurrent-VPN validation results.
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

## Completed: Tuntom and Saslik integration

- [x] Authenticated dynamic Tuntom sessions, lease renewal and automatic recovery.
- [x] Paired Saslik endpoints, remote health/status and advertised services.
- [x] GUI and TUI connection controls and transport selection.
- [x] CA download and supported NSS/system trust installation and removal.
- [x] Rotated diagnostic logs, Troubleshoot exports and actionable tunnel preflight.

## Follow-up

- [ ] Advertise additional local application trust stores through a future
  authenticated Skewer capability channel.
- [ ] Extend support-package collectors when additional platforms are supported.
