# ADR-0062 — Userspace network PIO adapter

Status: Accepted — source adapter; portable/target checks and guest admission remain separate
Date: 2026-11-12
Related: M6-04/M6-06; ADR-0042/0058/0059; E-006.8–12; E-011.10/14/21/29/31

## Decision

Implement the actual NE2000 byte-register adapter as the separate
`ev-net-driver` userspace crate. Use existing live scoped PORT_INPUT35 and
PORT_OUTPUT36 through the four-output ABI; reject malformed results rather than
truncating values or treating unexpected output/capability fields as success.
No NIC policy, packet parser, destination rule or DMA authority enters the Kernel.

The selected reference remains conditional on actual QEMU/source qualification
under ADR-0058. The library's `Ports` trait permits portable I/O models; the real
`Mediated` implementation performs the syscalls. No host networking API, TAP,
host NIC access, heap allocation or external dependency is required by this
adapter. Higher-layer networking will use a separate userspace stack boundary.

## Actual operation path

Cold initialization first verifies STOP, masks interrupts and aborts remote
transfers. The reviewed reset-port read establishes PROM/reset state only.
Validate its duplicated PROM bytes against the trusted expected unicast MAC.
Configure eight-bit data operations and one explicit packet area; no guest
physical packet address is accepted. Restore and verify full packet-RAM bounds
before scrub: stale PSTART/PSTOP can otherwise wrap an apparently long zero and
verification loop through only a small region, leaving old packet bytes intact.
Overwrite and independently read all16KiB, then configure and read back the
selected ring/MAC before declaring Prepared. Start is a separate checked step.

TX validates60–1514 bytes, preloads exact local RAM, clears prior TX status,
issues one actual command and checks fresh ISR/TSR. Any failure after the command
was attempted retains MayHaveSubmitted uncertainty and quarantines; no accepted
TX is retried. A success receipt means local device completion, not remote receipt
or successful higher-level transfer. Submission uncertainty is distinct from
whether other preparatory registers/RAM were already mutated.

RX reads the actual producer page, validates the complete header with the bounded
ring helper, reads at most two local spans and checks fresh error/overflow status.
Only then does it advance the consumer boundary. Error returns never publish a
partially copied frame. One call consumes at most one frame; higher-level turns
and finite shared queues provide backpressure rather than an unbounded drain.

Each mutating operation quarantines until its full readback/completion succeeds.
All status/data instructions share one checked absolute monotonic deadline and
finite step count, including when the clock stalls. Periodic yield preserves
other supervised work. Cooperative stop verifies STOP, restores transfer bounds,
scrubs/readbacks packet RAM and ends the instance; it does not automatically
restart or prove Kernel capability/CPU/memory quiescence.

## Admission and lifecycle boundary

The separate `probe` image uses the existing v1 startup layout with one exact
IoPorts role, a source-declared local-development MAC, bounded operations and a
measured16KiB RW/NX stack with absent guard pages. This compiles a real entry and
syscall path; it does not by itself admit/dispatch the image. The producer and
Kernel owner must measure linked pages/stack and charge actual resources before
adding it to a trusted graph. An incompatible or broader startup refuses.

Root retains authority to bind only the selected device, fence the old actor,
revoke its lineage, finish accepted work and establish exclusive recovery before
replacement. Ports remain with the driver; applications receive scoped network
session authority. Actual outstanding work, denied/stale authority, complete
retirement and continued local operation must be demonstrated before device
recovery or M6 networking PASS. Host/remote packets already emitted cannot be
retracted by resetting this device.

The initial portable tests and bare-target compile/stack checks are source
verification only. Actual source-pinned isolated packet I/O, stop/scrub readback
and live failure/replacement remain required, as do address configuration, DNS,
reliable permitted transfer and unauthorized/destination denial in M6-06.
