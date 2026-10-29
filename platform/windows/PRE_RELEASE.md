# Windows tunnel-first pre-release checkpoint

Validated on 2026-10-29 in the Rhino Windows 11 development VM.
This checkpoint records a working tested configuration, not general availability
or a claim of complete Linux parity. No public release or tag is created here.

## Artifact identity

Application and test ZIPs are version 0.9.50.6, built from `b639018`.
Changes between that build and this checkpoint are documentation only.

- Application SHA-256: `4ad25e0f27a9b59ab5727a28fbebe03785f0301d39efe1c57e7b2cf49c13e8dd`
- Tests SHA-256: `60a977923de481b1faa6c675d30e2e9a4e3cdfc730834d63e8c3d6ea1dca7aa2`
- Runtime: signed Wintun and WinDivert, privileged routing service, Qt GUI.
- No Npcap dependency or installation.

## Revalidated results

The same extracted application/test pair passed package verification and all
44 native tests. Noninteractive window checks are explicitly skipped by the
unit runner; the following integration runs exercised the interactive GUI.

`selected-service-live.ps1` passed root, new and adopted descendant HTTPS,
DNS/UDP, pre-Attach TCP reset, unique pre-Attach UDP routing, IPv6 blocking and
Release recovery, singleton handoff, independent application Release, and
protected pause across GUI termination/reopen. Routes and DNS were unchanged.

`native-routing-service-live.ps1` passed with `-TestPause -TestTunnelLoss
-TestGuiPause`: HTTP/HTTPS and system DNS traversed the tunnel; loss blocked
public traffic instead of falling back directly; restored peer connectivity
preserved user pause until explicit Resume. GUI termination preserved routing.
Stop removed the temporary service, owned routes and adapter.

No source fixes were required by these runs. Earlier installation smoke results
for these same artifact hashes are recorded in README.md; installation smoke was
not rerun as part of this checkpoint. The installed development service is not
implicitly upgraded by these disposable-service tests.

## Scope and limitations

Selected applications use IPv4 TCP/UDP through Tuntom. Whole-host tunnel routing
is supported; whole-host Direct exists but was not revalidated in this run.
Per-application Direct is deferred to research, by user decision.

IPv6 is blocked rather than tunneled. Service/WinDivert owner failure can remove
interception and restore direct connectivity: this is a lab tool, not a security
boundary. Arbitrary process delegation, VPN coexistence, endpoint relocation,
and broader network combinations remain separate validation/implementation work.

## Next phase

Research per-application routing without a tunnel or Npcap. Do not introduce a
custom kernel driver without an explicit architectural decision. A candidate
must prove selected and unrelated applications reaching the same destination
via different gateways, including return traffic and failure behavior.
