# ADR-0063 — Bounded userspace network stack

Status: Accepted implementation choice; portable and actual network gates remain separate
Date: 2026-11-12
Related: M6-04/M6-05/M6-06; ADR-0058/0059/0062; E-011.10–14/19–24/28–31

## Decision

Use exactly smoltcp0.14.0 behind the new Core `ev-net-stack` userspace boundary.
The [official tagged manifest](https://raw.githubusercontent.com/smoltcp-rs/smoltcp/v0.14.0/Cargo.toml)
declares0BSD and Rust1.91. Disable all default features and select only Ethernet,
IPv4, DHCPv4, DNS, UDP, TCP and Reno plus explicit finite configuration sizes.
Do not enable std/alloc, host raw-socket/TUN/TAP access, async, fragmentation,
multicast or Cubic. Preserve the exact dependency lock/checksums, upstream text
and transitive licenses in the root-owned inventory; no source is relicensed.

Protocol processing and configuration remain userspace. Existing Kernel
capability enforcement, scheduling, IPC and memory/device ownership mechanisms
remain their respective boundaries. This is a replaceable implementation choice,
not a Stable socket/driver ABI or a foundational change. The initial declared
virtual path is IPv4; IPv6 remains architecture direction for later path scope.

## Storage, work and transport

The owner lends four RX/four TX frame slots, exactly three socket slots, two DNS
queries and4096-byte RX/TX buffers for one TCP socket. Interface capacity is two
addresses/two routes/eight neighbors; DNS is bounded to two servers/two results
and255-byte names; TCP assembly uses at most four segments. These are explicit
initial profile sizes, not entitlements to uncharged memory. The executing
service's full linked stack/image/mappings must be measured and admitted.

The [device-token contract](https://raw.githubusercontent.com/smoltcp-rs/smoltcp/v0.14.0/src/phy/mod.rs)
maps onto borrowed fixed slots. Only the trusted MTU-bounded stack invokes the
non-fallible token length callback; raw application/IPC lengths never call it.
Short Ethernet frames receive zero padding to the selected NIC's60-byte minimum.
Saturation exposes backpressure. Actual outgoing-frame submission pins one slot;
independently checked driver completion releases it, while uncertain submission
retains bytes and quarantines. This local bookkeeping is not a remote ACK or a
shared-memory quiescence receipt.

Each service turn calls the tagged [single-ingress and egress APIs](https://raw.githubusercontent.com/smoltcp-rs/smoltcp/v0.14.0/src/iface/interface/mod.rs),
never its all-ingress drain loop. Queues bound emitted work and memory; actual
preemption, per-Job quotas, deadlines and accepted-operation cancellation remain
mandatory. In particular, [protocol random port selection](https://raw.githubusercontent.com/smoltcp-rs/smoltcp/v0.14.0/src/rand.rs)
contains rejection without an explicit iteration limit. No exact instruction or
whole-call real-time bound is inferred from finite queues or library API prose.

## Configuration, identity and trust

The wrapper applies actual DHCP changes to its address/router/DNS state and
distinguishes an emitted request from a lease. No fixed address is presented as
automatic configuration. DNS query tickets add current service incarnation and
fresh generation checks around the upstream slot API, refusing stale/duplicate
cancel/result operations before an upstream free-slot panic. Neither those
tickets nor source ports, IP addresses or DNS names are capability authority.

The actual network service authenticates protected client identity and checks
destination/session permissions before connect/query. It must revalidate resolved
addresses under that policy; DNS does not authenticate a host. Keep unauthorized
apps and raw-NIC access outside that service boundary. Offline/link/failure
states remain explicit while local apps, data and recovery continue to work.

smoltcp's internal sPCG protocol randomness is not a system CSPRNG or TLS key
source. The seed must come from the qualified service for security profiles,
without inferring cryptographic unpredictability of every upstream use. TLS,
release signatures, anti-replay/freshness, downloaded execution and preserved
KnownGood/data recovery remain separate M6-05/07/08 work. No transport response
alone authenticates an update.

## Validation boundary

Portable tests must cover real upstream DHCP packet generation, one-ingress
turns, malformed/saturated queues, zero padding, pinned uncertain submission,
clock regression and DNS slot reuse/cancel safety. Target checks establish
no_std compatibility only. Actual guest address configuration, DNS, reliable
allowed transfer, unauthorized/destination denial, link failure and driver/service
restart/retirement remain required before M6-06 PASS. External network/hardware
or consumer security qualification is not inferred from model tests.
