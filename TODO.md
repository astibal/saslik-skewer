# Skewer roadmap

## Next: minimal local routing

- Keep application selection and process movement in `skewer-routed.slice`.
- Add an explicit, configurable next-hop IP for traffic from that cgroup.
- Install narrowly scoped packet marking and policy-routing rules.
- Keep all unrelated host traffic on its existing routes.
- Make setup, status and teardown idempotent and visible in both the GUI and TUI.
- Document that sockets opened before an application is attached retain their
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
