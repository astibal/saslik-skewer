# Portable packet identity

## Observed flow index

`skewer-flow-index` correlates decoded tuples with explicitly supplied flow
observations. The Windows `TrackedFlowObserver` now feeds it live FLOW events;
live packet capture is not yet connected. Its key includes PID, process creation time
and endpoint ID; it never derives process ownership from an executable name.
Both directions share a canonical tuple. Multiple sockets of one process still
have one observed owner; distinct process identities produce `Ambiguous`.
Lookups are indexed by tuple, not a linear scan of every observed flow.

Results are `Unknown`, `Observed`, `Ambiguous` or `Unreliable`; only `Observed`
contains an identity, and that means **observed**, not authenticated ownership.
The caller must supply comparable source timestamps and nondecreasing steady
clock times, serialize access, and signal detected observation loss through
`invalidate()`. Undetectable driver event loss remains undetectable here too.

Closed endpoints retain tombstones. Delayed opens cannot resurrect them, and
equal timestamps prefer closure. Conflicting endpoint metadata, capacity overflow
or explicitly expired context invalidate the index rather than silently evicting
a competing owner. Lookup itself never returns expired observations. Defaults
are 4096 records (including tombstones) and five minutes of context lifetime;
the caller runs `expire()` periodically. Expiration requires starting a new
observation epoch, not automatic "recovery" with incomplete history. `reset()`
is only valid after old producers have stopped and their queued events cannot
enter the new epoch. No locking, background thread or network policy is hidden
in this library.

Tests include reverse packets, duplicate same-process sockets, conflicting
owners, PID reuse, out-of-order events, deletion-before-open, timestamp ties,
capacity exhaustion, context expiration and explicit epoch reset.

## Packet decoding

`skewer-packet-tuple` decodes source/destination addresses and ports from complete
IPv4/IPv6 TCP/UDP L3 packets. It has no Qt, Windows, driver or tunnel dependency,
allocates no memory while parsing, and never changes the supplied packet.
Addresses use network-order bytes; ports use host-order integers. IPv4 occupies
the first four address bytes with a zero tail. The explicit family distinguishes
IPv4 from IPv4-mapped IPv6. `reversed()` exchanges both endpoints.

This is a building block for future packet/flow correlation, **not an application
ownership oracle or routing policy**. A tuple can be reused or shared, FLOW events
can be lost, and first packets can arrive before an observation. Matching a tuple
alone must not grant permission to bypass the persistent kernel guard. The module
is not yet connected to WinDivert packet capture or TunnelPump.

The parser requires exact IP lengths and complete transport headers, validates
TCP data offset and UDP length, and ignores checksums (outbound capture can occur
before checksum offload). It is not a full IP protocol validator. It rejects:

- IPv4 fragments, including first fragments; IPv6 Fragment headers, even atomic.
- IPv4 options and IPv6 routing headers, AH/ESP and non-TCP/UDP protocols.
- IPv6 non-padding extension options, including Home Address and Jumbo Payload.
- More than eight supported IPv6 extension headers or malformed/truncated data.

Hop-by-hop (first only) and Destination Options headers containing only Pad1/PadN
are supported. An unsuccessful result never contains a tuple. Its status describes
why attribution cannot proceed; it must never mean "send directly instead".
No reassembly, ICMP error correlation, NAT, checksum repair or injection exists here.

## Tests

Both application builds include the `packet_tuple` CTest. A standalone Linux
sanitizer build needs only CMake and a C++20 compiler:

```sh
cmake -S platform/traffic -B /tmp/skewer-packet-test \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build /tmp/skewer-packet-test
ctest --test-dir /tmp/skewer-packet-test --output-on-failure
```

Tests cover both families/protocols, byte order, reversed identities, every prefix
truncation of basic packets, contradictory lengths, fragmentation, extension
bounds/options, and a seeded 30,000-input hostile corpus. The same executable runs
on Windows without elevation or a network driver. This corpus is regression
coverage, not exhaustive fuzzing or proof that all packet formats are supported.
# Bounded pending packets

`PendingPackets<Context>` owns captured bytes and fixed-size capture metadata
while attribution is pending. It is single-consumer and noncopyable, independent
of Windows, Qt and Tuntom. Limits cover packet count and retained payload/metadata
bytes (not allocator overhead). New packets are rejected when full; existing
entries are not evicted to make room. Deadlines use a monotonic clock and are
checked on hold/take or explicit `expire()` calls; the service must schedule
expiry while idle. No background thread is created by this container.

Tickets are never reused within a queue lifetime. Consumption is one-shot and
cannot revive expired entries. `stop()` discards everything and permanently
rejects further input; it does not drain packets onto the network. A new observer
epoch requires a new queue and must not reuse the old epoch's tickets.

This is storage, not authorization: `take()` does not prove ownership, select a
route or check tunnel readiness. A service must make those decisions separately.
The Windows VM fixture uses it for captured UDP and TCP SYN packets; it is not
yet wired into a production interception service.

## Selected packet gate

`SelectedPackets<Context>` adds a single-process, single-epoch outbound policy
queue. It parses the actual held packet and supplies that tuple to a trusted
resolver at release time. Unknown/ambiguous ownership remains held until expiry;
another process (including the same PID with a different creation time) is
discarded. Only a unique matching owner with a live process and healthy tunnel
can release bytes. Missing unique-owner identity, unreliable attribution,
resolver exceptions, process exit or tunnel failure retire the entire queue.
Retirement is terminal: reconnect requires a new queue/epoch. There is no direct
network fallback. Unsupported/fragmented packets cannot enter this queue.

The resolver contract intentionally does not accept `FlowIndex::Match` directly.
Observed ownership alone does not prove uniqueness. Liveness and health are
fresh inputs from the single owning worker, not background checks performed by
this container. The owner must also stop downstream work on failure and schedule
idle expiry. This is not yet a complete interception/routing service.

Tests cover delayed/ambiguous resolution, expiry, one-shot tickets, PID reuse,
retirement and exceptions. The Windows live fixture additionally uses the gate
before the real encrypted TCP/UDP round trip, with pinned process liveness and
actual tunnel health. Its ownership evidence is the fixture's exclusive sockets,
not an assertion that a per-process observer is a general ownership oracle.
