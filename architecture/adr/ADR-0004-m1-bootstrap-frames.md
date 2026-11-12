# ADR-0004 — M1 bootstrap physical frames

Status: Accepted
Date: 2026-09-30
Owners: Project owner; kernel and boot-contract maintainers
Related: E-002, E-005, E-025.18, E-025.22, INV-KERN-001, INV-KERN-004, INV-KERN-005, INV-M0-004, INV-EVO-001, INV-EVO-002

## Context

The owner authorized M1 and then instructed implementation of its first memory
slice. Page-table construction needs a bounded way to select usable physical
frames without a heap. The existing boot contract supplies a validated, sorted,
non-overlapping map of at most 512 regions; unknown loader types remain reserved.

## Decision

Add an allocation-free monotonic bootstrap frame allocator in the kernel's
portable `no_std` library. Consume the validated MemoryMap by value and hand out
whole 4 KiB frames from usable regions, excluding page zero and partial pages.
Keep one cursor, exact remaining counts and an explicit exhaustion error. No
free/reuse, arbitrary physical-pointer conversion, mapping or zeroing is exposed.
Frames and allocator state are not Copy or Clone. Initialization is once per
boot; rebuilding a map does not confer physical ownership or authority.

Transfer BootInfoV0 into the kernel entry by value so its map can move into the
allocator without another memory-map copy. This changes only the Internal Rust
handoff signature and its sole call site. Loader-specific types remain inside the
adapter. No new loader feature or dependency is introduced; EXC-0001 retains its
existing scope and expiry.

The kernel performs a bounded two-frame smoke check against the real map, verifies
that the frames avoid the kernel image, and emits a distinct M1 bootstrap record.
Keep the existing M0 serial/exit protocol for boot regression compatibility.

## Invariants preserved

- INV-KERN-001: physical allocation is a kernel mechanism; memory policy stays outside.
- INV-KERN-004: fixed map capacity, constant metadata, bounded scan per allocation.
- INV-KERN-005: allocator implementation contains no unsafe code.
- INV-M0-004: only validated Evrosion memory maps reach this constructor.
- INV-EVO-001 / INV-EVO-002: the adapter remains isolated; the handoff stays Internal.

## Alternatives considered

A bitmap or buddy allocator needs metadata placement, mapping and reclamation
design before the kernel can build its first page tables. An intrusive free list
would dereference unestablished mappings. Borrowing and repeatedly constructing
selectors over the same map makes accidental cursor resets easier. Move-owned,
monotonic allocation supplies the immediate bootstrap need with fewer assumptions.

## Consequences

Allocated frames remain claimed until a later allocator transition explicitly
imports that state. They cannot be returned yet. The caller must retain one
allocator for the boot lifetime and may not reconstruct ownership from an address.
The initial smoke check halts afterwards, so no frames are reused in this slice.
Multiple CPUs and interrupt-context allocation require a later synchronization
design; the current entry has interrupts disabled and a single mutable owner.

## Security and failure analysis

Reserved, loader and kernel memory are never reclaimed. Arithmetic relies on the
validated physical-address bound of 2^52. Partial pages round inward. Empty usable
space is valid but allocations return Exhausted. No returned address is safe to
dereference merely because it was selected; zeroing, mappings, permissions,
capability checks and user isolation are separate later obligations.

## Verification

Host tests exercise discontiguous ranges, reservation boundaries, alignment,
page zero, maximum physical addresses, exact counts, repeated exhaustion, and
bounded-map coverage against an independent page-containment oracle. Adapter
negative cases continue to reject malformed and overlapping input. Real QEMU
boots must emit a checked M1 bootstrap record plus the existing success protocol;
panic/serial-only regressions remain required. Executed results are linked from
the M1-01 task only after verification.

## Migration / rollback

The later reusable allocator must import claimed ranges without reissuing them.
Keep the M0 tag and historical evidence intact; new implementation/proofs belong
to M1. The by-value handoff has no external callers or Stable compatibility promise.

## Expiry or review trigger

Review before page-table integration, reclaiming any memory, SMP/interrupt access,
user exposure, or boot-contract Preview.
