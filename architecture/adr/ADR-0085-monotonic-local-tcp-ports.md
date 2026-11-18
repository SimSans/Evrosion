# ADR-0085 — Monotonic local TCP ports

Status: Accepted Internal mechanism; controlled guest qualification pending

Date: 2026-11-13

Decision level: B

## Evidence and problem

The immutable TimePause07 cohort completed DHCP, DNS and the first Hello
transfer, but never completed its second TCP connection. Its actual Root
failure snapshot recorded Connecting, last validated TCP state SynSent and
118 exchange work steps. The owned QMP `info usernet` observation independently
showed `TCP[TIME_WAIT]` for `10.0.2.15:49152 -> 10.0.2.2:8080`.

The service selected the same immutable local port for every connection. The
observed guest and virtual-peer states support avoiding immediate tuple reuse;
no packet capture is claimed. The later Kernel rejection was a separate correct
deadline guard: a proposed Driver child cut19186 exceeded a queued Root parent
cut19134. That guard remains intact. No completed time proof, VM pause,
post-pause check or cooperative shutdown was established by this failed run.

The exact state observation is retained in the owned07 origin and the compact
audit SHA256 `2a1838cbf875e405bf7fab7179869a308d7950a5c60b2f407beb1c5c236d54c9`.
Its original240-second failure, raw serial, unchanged4MiB disk and source and
artifact postflights remain preserved.

## Decision and compatibility

Under the versioned V4 contract, Root's checked Initialize `local_port` is the
inclusive first allowed ephemeral port, at least49152. One service incarnation
allocates monotonically through65535. The existing notice, sequence, canonical
shared-frame, lease and exact remote destination checks precede consumption.
Root's existing DNS validation remains unchanged.

Consume a port before calling the actual single upstream TCP socket's connect
operation. A failed or refused socket transition still consumes that port.
Closing or retiring a socket cannot replenish the allocator. At65535 the next
value becomes absent; subsequent connection attempts return Refused before any
socket mutation. There is no wrap, random collision retry, reset API, new socket
or growing collection. This is bounded private metadata, not network authority.

The additive V4 ABI description binds these semantics. Its exact suffix is:

```text
; local TCP port allocation v2: Initialize.local_port is inclusive ephemeral floor49152..65535; single socket allocates monotonically before each validated scoped Connect attempt; failed attempts consume; no wrap/reset/reuse within one service incarnation; exhaustion Refused; remote IPv4/port/name scope unchanged
```

The existing S1 control bytes and opcodes are unchanged. The new semantics apply
only to the measured V4 cohort with its corresponding ABI and actual retained
actor identities. This does not relabel the older Native3 contract. Main's other
capacity amendments remain independently versioned; a controlled07-to08 test
imports only this suffix and its recomputed hash, rather than importing those
unrelated changes.

All remote address, port and name restrictions, one-socket storage, CPU quotas,
RPC and transaction deadlines, work caps, shared-window ownership and device
retirement rules remain unchanged. Accepted unknown work is never retried by
this allocator. No socket reset or abort is added to production transport.

## Incarnation boundary and remaining recovery work

This first mechanism retains its high-water mark within one service incarnation.
It does not establish safe reuse after replacing NetService on a still-running
virtual network. Before claiming replacement reconnect recovery, Root must
retain a nonreused range/high-water reservation across that replacement, hand
the new service a fresh range, and refuse exhaustion. It must not reconstruct a
fresh allocator over potentially live old tuples or infer that CPU exit/NIC
scrubbing retracts prior network sessions. These remain explicit M6 recovery
gates; the two-connections/one-incarnation test does not close them.

## Validation

Meaningful models exercise every ephemeral port through exhaustion, the actual
single upstream socket's selected local endpoint, consumption on a failed
connect, and a fresh port after model socket retirement. Canonical ingress,
missing lease, stale requests, malformed controls and repeated Initialize cannot
replenish or consume the range improperly. Model-only socket abort is confined
to tests and is never a runtime recovery claim.

Controlled08 must derive from immutable07 with only this mechanism, the V4
suffix, tests and this ADR. Its own actor/image admission, guarded stack census,
source postflights and original240-second TimePause workflow remain required.
Until that execution is retained, no new guest transfer, clock or recovery
success is claimed.
