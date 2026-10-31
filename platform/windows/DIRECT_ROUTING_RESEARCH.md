# Per-application Direct routing: initial research

2026-10-29, after the tunnel-first pre-release checkpoint `387be79`.
Research only: no new driver installed, no replacement backend implemented.
Npcap is excluded by user decision.

## Two-adapter native experiment: forwarding works, loss leaks

On 2026-10-29 an isolated Windows VM experiment used the existing WinDivert
driver, without changing the production backend or installing another driver.
Exclusive TCP/UDP sockets belonging to the probe were selected by their reserved
port 48101; a control socket used 48102. This is not a general PID-selection test.

Topology:

```
original NIC: 192.168.199.131 -> 192.168.199.1 (virbr0)
temporary NIC: 198.18.240.2 -> 198.18.240.1 (skw-direct-test)
same target for both: 198.18.241.1:18087, local echo server on Rhino
```

Both NICs had WeakHostSend/Receive disabled. The temporary default route had a
higher metric. The probe rewrote only the selected outgoing source address and
restored the original destination address/interface on replies. No alias DNAT,
remote NAT, tunnel, production routing change or Internet dependency was used.

- Healthy: TCP and UDP replies reported the expected source addresses. Capture
  on Rhino showed selected traffic on vnet9/skw-direct-test and control traffic
  on vnet5/virbr0, with replies on the corresponding paths.
- Temporary NIC disabled, translator still alive: control TCP/UDP succeeded;
  selected calls timed out. **Capture nevertheless showed selected UDP and TCP
  SYN packets with source 198.18.240.2 leaving through virbr0.** Source rewriting
  alone therefore does NOT provide fail-closed routing. A timeout is not proof
  of no leakage, and the probe's exit-zero expected-timeout result is not a
  security pass. WinDivert reported no send errors in this case.
- NIC restored: selected and control TCP/UDP succeeded again (6 translated
  outbound and 6 inbound packets, no send errors in the repeat).
- Closing the translator in the first healthy run also allowed a delayed TCP
  FIN to take the original path, consistent with the documented owner-loss limit.

These were sequential socket probes to one local target, not concurrent load,
HTTPS through Smithproxy, general process ownership, MTU/fragmentation, or
same-NIC different-gateway validation. The temporary NIC, bridge, host target
address, Windows address/default route and echo process were removed afterwards;
the VM again had only its original NIC. Probe sources remain in /tmp as
skewer-direct-probe.cpp, skewer-direct-run.ps1 and skewer-direct-peer.py.

Conclusion: the healthy-path mechanism is real, but the unguarded proposal is
unsuitable for integration. A further prototype must enforce egress identity
independently of successful reinjection and validate adapter loss with capture.
Polling adapter health alone cannot eliminate a check/send race. Direct remains
opt-in if it ever requires an additional adapter; Tuntom stays the default.

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
