# Bounded userspace network stack adapter

Internal adapter around exactly smoltcp0.14.0, with default features disabled.
Ethernet/IPv4/DHCPv4/DNS/UDP/TCP and Reno are selected. There is no std, alloc,
host raw-socket/TUN/TAP backend, async, fragmentation, multicast or Cubic feature.
The first exercised path is IPv4; this does not remove the later IPv6 direction.

The actual owner supplies/charges all storage: four RX and four TX frames, three
socket slots (DHCP, DNS, TCP), two DNS query slots, and fixed4096-byte TCP receive
and send buffers. Interface addresses/routes, neighbor cache, DNS names/results
and TCP assemblers have explicit finite compile-time capacities. Heap growth is
not a fallback for saturation. The final executing service must measure its
actual linked image, stack, storage and per-Job admission before dispatch.

`Queues` implements smoltcp's device-token boundary over borrowed slots. A small
emitted Ethernet frame is zero-padded to60 bytes before the NIC sees it. One
actual transmission is marked in flight; only the independently authenticated
driver completion releases it. Uncertain submission quarantines the queue and
retains its bytes rather than automatically resending. TCP-level retransmission
is a separate transport policy after actual driver/lifetime recovery.

`Stack::turn` performs one ingress attempt and one egress pass, then returns.
It never invokes the upstream all-ingress drain loop. The actual scheduler must
yield between turns, enforce deadlines and contain abusive workloads. smoltcp's
DNS source-port rejection loop has no explicit iteration cap; fixed storage and
packet batching are not a formal per-call CPU bound. Runtime preemption and
operation cancellation remain required.

DHCP events update the current IPv4 address, default router and at most two DNS
servers. Sending a discover alone is not a lease or connectivity proof. DNS query
tickets carry the actual service incarnation and fresh generation so duplicate,
canceled or reused-slot requests refuse before calling upstream APIs that panic
on a free query slot. Socket handles and DNS results are not capabilities.

The actual service must authenticate each client and authorize destinations
before exposing connect or lookup. Address configuration and DNS do not grant
authority, and DNS answers do not establish server identity. smoltcp supplies no
TLS, release signatures or update freshness. Its internal protocol PRNG is not
the system CSPRNG; source/DRBG qualification remains M6-05. Deterministic model
seeds cannot become a security acceptance claim.

The pinned dependency is0BSD; its upstream text/provenance and transitive terms
must remain in the root-owned dependency inventory. This wrapper is Core code,
not a Stable public SDK. See
[ADR-0063](../../architecture/adr/ADR-0063-bounded-userspace-network-stack.md).
