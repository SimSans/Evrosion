# ADR-0042 — Scoped userspace PIO reference backend

Status: Accepted
Date: 2026-10-27
Owners: Project owner; kernel/platform maintainers
Related: E-006.8–9; E-010; E-025.34–44; ADR-0039

## Decision and architectural fit

Start M3 with one isolated, non-DMA QEMU ISA ATA PIO device and a source-built
userspace driver. Keep device commands, polling, block semantics, flush handling,
journaling and generation policy outside the kernel. The kernel implements only
live port-capability validation and one authorized input/output instruction.

E-025.35 names VirtIO as preferred. E-025.36 explicitly permits a primitive first
backend behind E-010's stable File/Object, immutable/mutable and durable-operation
boundaries. E-006.8 explicitly defines device-scoped IoPorts authority. This is a
Level B implementation choice under the founder's engineering mandate; none of
the owner-control, isolation, recovery or storage guarantees change. VirtIO can
replace the backend after its DMA containment and lifetime contract exist.

The local QEMU 10.2.1 device model supports a separate `isa-ide` controller at
ports 0x1e8/0x3ee, IRQ10, with one private raw test disk. The boot disk remains on
its existing Q35 controller. Sharing its channel would let a raw port holder
select that disk, so a sector convention cannot substitute for this separation.
The [QEMU ISA realization](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/ide/isa.c)
uses the [IDE core's](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/ide/core.c)
no-op DMA implementation without a start callback. That supports this specific
guest-memory-DMA boundary; it says nothing about arbitrary physical controllers.

## Authority and instruction boundary

IoPorts is Internal kind tag7. READ authorizes input and WRITE output; neither
means a disk-sector permission. Trusted binding fixes up to four port extents,
width masks and directions against the complete object generation. Different
objects cannot overlap assigned byte ports. Only trusted actual-resource binding
can mint this hardware authority; ordinary Job CONTROL cannot create IoPorts.
Only the driver receives raw ports. Applications receive typed storage objects.

Each syscall derives the actual running Scheduler thread and registered RPC
domain, validates the live capability ancestry/kind/rights and exact binding,
then returns a non-cloneable permit borrowing that authority and binding. The
binary helper consumes it for one width-selected instruction. User parameters
cannot supply a PID, domain, policy range or alternative object generation.
Full-width port, width and output-value validation precedes the instruction.

Input35 uses capability/port/width and zero R10. Output36 uses the same operands
and R10 value. Both return status and input value, clearing other result operands.
This is an additive Internal scalar interface, not a stabilized public driver ABI.
Direct CPL3 port access remains denied by the TSS/IOPL boundary.

## Persistence and lifecycle limits

The first hardware workflow creates its own unique repository-local data image,
seeds it, runs write/flush/readback, and reopens the same image in a fresh VM with
a separately measured verify program. Host evidence checks the exact allowed
sector change, unchanged guard bytes, unchanged verify image and boot image,
complete ordered serial protocol and actual QEMU exit status. Default M0/M1/M2
boots do not attach the disk. No arbitrary host path is exposed to the guest.

No guest-memory DMA does not mean no device work. An accepted PIO write can
remain in progress asynchronously. Measured userspace must bound BSY/DRQ/error
polling, finish/drain commands and check flush completion. A successful actor
exit is evidence for this narrow development flow; it is not a general device
quiescence witness. The device-free BAC receipt from ADR-0039 cannot certify
device-bearing Root reconstruction. Driver restart must gain its own drain/reset
and durable-operation recovery before being claimed.

Fresh-VM reopen proves persistence across guest restart, not host physical power
loss. A block proof alone does not complete M3. Checksummed staging, durable
journal/commit, interrupted-operation recovery, immutable generation selection,
real health failure, Known-Good rollback and mutable-data preservation remain
required. Device commands must remain below these replaceable logical contracts.

## Validation

Portable adversarial tests cover actual caller binding, attenuation/revocation,
forged/stale objects, port overlap, width/direction/value bounds, atomic refusal
and generation-safe metadata retirement. Target lint validates the binary-only
instruction boundary. Actual guest I/O and cold-reopen results must be linked in
the canonical project tracker before any hardware or persistence PASS claim.
