# Skewer roadmap

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
