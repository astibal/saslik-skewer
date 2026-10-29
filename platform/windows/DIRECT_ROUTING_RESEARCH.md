# Per-application Direct routing: initial research

2026-10-29, after the tunnel-first pre-release checkpoint `387be79`.
Research only: no new driver installed, no replacement backend implemented.
Npcap is excluded by user decision.

## Required distinction

Choosing a NIC is not choosing a next hop. Two applications reaching the same
IP must be able to use different gateways without changing the unrelated
application's route. Transparent SOCKS/CONNECT is a possible separate feature,
not evidence of satisfying this contract. Tuntom remains the tested transport.

## Findings

- WinDivert NETWORK outbound injection ignores interface indices, as described
  in its [injection contract](https://reqrypt.org/windivert-doc.html#divert_send).
  Host destination routes alone cannot distinguish applications.
- The kernel [forward injection API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsinjectforwardasync0)
  exposes a routing compartment and destination interface, not an explicit
  gateway parameter. Its existence does not prove a usable same-NIC next-hop
  override through the current WinDivert user API. This remains a separate
  investigation; do not claim that changing a NETWORK IfIdx completes it.
- Windows [layer-2 injection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-layer-2-filtering)
  can send constructed MAC frames through a callout driver. This is a plausible
  architectural route to explicit next-hop MAC selection, not an implemented
  backend. It requires neighbor resolution, return-path validation, checksum/
  offload handling, loop avoidance, adapter changes and signed-driver lifecycle.
  A custom driver remains outside the first release and needs explicit approval.
- The public [SetCurrentThreadCompartmentId documentation](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setcurrentthreadcompartmentid)
  explicitly says not to use the function. Even a private compartment experiment
  would not establish safe migration of arbitrary running applications and their
  existing sockets. It is not a supported drop-in cgroup equivalent.

## Recommendation and next evidence

Keep the pre-release on the verified tunnel path. No supported, dependency-free
per-application next-hop implementation has been established by this research;
that is not a proof of impossibility.

Before considering a driver, inspect WinDivert's forwarding injection path and
test whether a supported combination of interfaces and routing compartments can
actually distinguish the same-destination traffic. Reject any candidate that
only works by globally changing that destination's route. If only L2 injection
survives the investigation, present its driver/signing/maintenance implications
as an architectural decision rather than silently modifying WinDivert.

Any prototype needs simultaneous selected/unselected TCP and UDP traffic to the
same target, packet capture at both gateways, verified replies, packet-loss and
gateway-loss cases, Release, GUI closure and cleanup checks. Do not substitute
a successful curl for this isolation evidence.
