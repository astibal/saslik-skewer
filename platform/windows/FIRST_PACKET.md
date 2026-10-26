# First-packet decision: experiment and design boundary

## Verified in the development Windows VM

The opt-in `tests/first-packet-live.ps1` runs a same-user fixture with a retained
process identity. All traffic is loopback, using fresh TCP/UDP sockets and
ephemeral ports, for both IPv4 and IPv6. No default route, browser or persistent
WFP policy is changed. The fixture waits on named events between three rounds:

1. Baseline: TCP connections and UDP datagrams are delivered.
2. Install WinDivert SOCKET `DROP | RECV_ONLY`, matching only the fixture PID,
   `CONNECT`, and TCP/UDP. TCP reports `WSAEACCES`; the first unconnected UDP
   datagram is not delivered within the receive deadline. A separate instance
   of the exact same executable still delivers all four traffic classes.
3. Forcibly terminate the retained filter-owner process. The same fixture PID
   opens fresh sockets again: all four traffic classes are delivered.

Result: **per-PID rejection of a new operation works, but protection disappears
after filter-owner termination**. The experiment intentionally confirms this
limitation; a passing test does not certify a kill switch. UDP send success alone
is not proof of delivery, hence the listener-side assertion. This is not a
physical-interface capture, reboot test, existing-socket test or child-process test.

Build with `SKEWER_WINDOWS_FLOW=ON`; place `first_packet_test.exe` and
`app_egress_guard_test.exe` beside the official WinDivert 2.2.2-A x64 files in
the VM test directory. The script checks the DLL/SYS hashes and driver signature.
Run elevated as the fixture user. It terminates only its own retained child
processes, and the experiment helper has a 60-second fallback lifetime. Never
use that ephemeral helper as production protection. It is excluded from CTest.

## Why FLOW plus a PID cache is insufficient

The [WinDivert layer contract](https://reqrypt.org/windivert-doc.html#divert_layer)
has distinct capabilities:

| Layer | PID metadata | Blocks | Reinjection |
| --- | --- | --- | --- |
| FLOW | Yes | No | No |
| SOCKET | Yes | Yes (operations) | No |
| NETWORK | No | Yes (packets) | Yes |

SOCKET blocking rejects an operation; it is not a queue from which a successful
connect can later be resumed or rewritten. Adding a NETWORK tuple filter after a
FLOW event cannot establish a first-packet guarantee. Capturing a broad packet
set before any application starts is a different design, with global queuing,
unknown-owner handling and independent crash-surviving protection still required.
Our diagnostic flow index is not that protection.

The existing persistent image guard also cannot be treated as per-instance
protection: it blocks every instance of that executable. Removing it to allow
the chosen process creates an authorization gap, not a safe handoff.

## Next implementation gate

For strict per-instance selection, investigate a small WFP callout at ALE
authorization before implementing a general packet forwarding loop. Microsoft's
[asynchronous classification contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously)
supports pending new ALE authorization, then completing and deciding during
reauthorization. Non-TCP data may also need to be cloned/retained and reinjected;
FLOW_ESTABLISHED is not an asynchronous authorization point.

The prototype must establish these properties before GUI Attach is enabled:

- Kernel-bound process identity, with PID reuse, selection and lifetime handled
  explicitly; no trust in a delayed user-mode PID-to-tuple observation.
- Kernel-side default deny for selected instances when the controller disappears.
- Bounded pending decisions, timeout-to-deny and no synchronous user-mode wait
  inside classify callbacks. Reauthorization is handled separately.
- A proved path for both initial and subsequent packets through the tunnel;
  granting connect is not proof that its route is the selected tunnel.
- Existing sockets, process descendants, shared DNS and IPv6 covered or visibly
  rejected as unsupported, never silently routed outside protection.
- Physical egress capture during first connect, tunnel/helper failure and recovery.

[ALE connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
is another WFP callout option if we choose a local connector. It needs redirect
records/context, loop prevention, and explicit TCP/UDP handling; it is not merely
a WinDivert flag. We have not implemented or selected that forwarding architecture.

A custom callout introduces WDK build, signing, installation, upgrade and recovery
work. This experiment does **not** install a custom driver, change Secure Boot,
enable test signing, or prove production driver persistence. Those are separate
decisions; no security setting should be weakened implicitly to run the prototype.
