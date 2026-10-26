# Portable packet identity

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
