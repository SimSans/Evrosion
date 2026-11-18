# ADR-0058 — Bounded ISA network device choice

Status: Accepted — reference choice and portable helpers; guest integration pending
Date: 2026-11-12
Related: M6-04/M6-06; E-006.8–12; E-011.10–14,20–24,28–31; INV-IPC-004; ADR-0042

## Decision

Select the QEMU `ne2k_isa` reference path for the first virtual network slice,
conditional on qualification of the actual QEMU binary and invocation. Keep the
NIC driver and all network protocol, configuration, destination and permission
policy in userspace. A separate driver receives only its exact byte-port extent;
apps receive scoped network-session authority, never raw NIC ports.

Start with the explicit 0x300–0x31f window, polling with device IMR zero and no
new guest IRQ authority. The existing live IoPorts mechanism checks every byte
instruction; direct CPL3 I/O remains forbidden. No PCI configuration, guest
physical-memory pointer, bus-master enable or new DMA authority is introduced.
This is a bounded implementation refinement, not a preferred physical NIC or a
replacement for eventual DMA/IOMMU containment.

## Source witness and qualification boundary

The reviewed upstream [v10.2.1 ISA realization](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/net/ne2000-isa.c)
registers a 32-byte I/O region and an ISA IRQ. The complete
[device core](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/net/ne2000.c)
and [state layout](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/net/ne2000.h)
place packet data in private `NE2000State.mem[]`: RX copies into it, TX reads it,
and remote-address/count registers access that array. The reviewed ISA/core
paths neither accept a guest physical packet address nor invoke guest address
space/bus-master memory operations. “Remote DMA” here names a device-local
transfer exposed through ports; its name is not a guest-memory DMA witness.

[Network transmission](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/net/net.c)
routes these bytes through the [host queue](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/net/queue.c),
which copies queued packet bytes. That does not promise remote delivery or
purge packets already accepted by host/remote networking.

The inspected local binary reports 10.2.1
`1:10.2.1+ds-1ubuntu3.2`, SHA256
`0cd4112a8f0cb891eb7c10e8df38c9dfeec8c7389bb22db6aa425f0d6fe733dc`.
Upstream source downloads, hashes and the local binary record are retained in
the local engineering archive. Upstream tag review does not
establish downstream patch equivalence, QEMU8.2 behavior or actual guest execution.
The eventual accepted profile must bind actual binary/version/command and either
verify its source-equivalent device path or refuse that unqualified profile.

## Bounded storage and API

`ev-net-device` is a dependency-free safe `no_std` helper crate. It validates
untagged frames of60–1514 bytes, one pending TX, and four owned local frame slots.
The conventional16KiB device packet area separates TX0x4000–0x45ff from the
RX0x4600–0x7fff ring. RX metadata validation covers status, length, exact next
page, producer extent and wrap before deriving at most two device-local reads.
An invalid header cannot authorize data copying or boundary advancement.

The local pool is finite and refuses saturation without altering accepted
packets. Generation plus actual incarnation bind ticket access/release; old
completion cannot release a replacement's slot. This is not a stabilized public
driver ABI and not the future shared Memory Object transport. Copies required
by this PIO backend do not change E-011's later zero-copy/batching direction.

Before integration, measure the linked driver/stack, exact local pool storage,
process/Job/capability slots, per-packet instruction/CPU cost and bounded shared
transport. Admit those actual resources against existing parent quotas rather
than silently enlarging every actor or object pool. Start no unbounded background
poll loop: preserve absolute deadlines, poll counts and ordinary scheduler turns.

## Stop, crash and retirement

The reviewed reset-port read calls `ne2000_reset`, which sets ISR/PROM values; it
does not itself stop the command engine, clear remote counts or erase the ring.
It must never be promoted to a false quiescence receipt.

The composed retirement must fence old dispatch and revoke its port lineage,
finish the actual in-flight instruction boundary, acquire exclusive recovery
authority, write STOP/no-remote-transfer, mask IMR, zero remote count and verify
actual STOP readback. Then scrub/reinitialize all owned packet RAM, clear status
and reconstruct bounded state before remint/start. An uncertain command or
failed readback quarantines the incarnation; do not retry an accepted send or
release externally shared buffers merely because a userspace counter changed.

Local completion does not establish remote delivery, and a driver restart cannot
retract network effects. Host/remote delayed packets remain untrusted input;
network-session identities and current transport state must prevent stale local
buffer/capability delivery. Generic protected Root/device reconstruction remains
outside this narrow helper and needs its own device-bearing proof.

## Validation and remaining gate

Portable tests exercise malformed/wrapped headers, producer overread, saturation,
stale/repeated completion, incarnation replacement, finite stalled-clock polling,
clock regression and quarantine after uncertainty. They prove helper behavior.
M6-04 remains open until an actual source-pinned isolated driver transfers
packets, denies unauthorized ports, survives live outstanding-work failure and
demonstrates real stop/drain/reset, revoked old authority and safe resource
retirement. M6-06 additionally requires actual address configuration, DNS,
permitted reliable transfer and destination/no-network denial. No host interface
reconfiguration or physical-device qualification is implied by this ADR.
