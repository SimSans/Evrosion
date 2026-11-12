# ADR-0019 — Quiescent private-frame reclamation

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0004, ADR-0007, ADR-0018, INV-KERN-003–005

## Decision

Extend the single-owner bootstrap allocator with 128 retained recycled claims.
Every non-copyable PhysicalFrame records its originating allocator identity.
Identities are atomically allocated without wrap; they are bookkeeping, not
capabilities. A different allocator cannot accept a claim, even if its memory
map describes the same addresses. A full recycle pool returns the original
claim to its caller. Allocation consumes recycled claims before new frames;
available-frame counts include both classes. Reuse counter exhaustion fails
without consuming a claim. Physical bytes are accessed only at the hardware
boundary, never by allocator bookkeeping.

A private UserRoot can relinquish its owned leaves and table frames only after
all process threads retire, the controller switches CR3, and no CPU or outstanding
alias can access those mappings. The BSP proof keeps the AP parked; the AP has
never used these roots. PCID is disabled and user leaves are nonglobal, so the
root switch invalidates their local translations. Shared mappings are excluded.

Before touching pages, teardown reads CR3 and rejects its own active root,
checks all frame provenance, and preflights recycle capacity. It clears the
private leaf table, consumes the software mappings, scrubs every owned data and
table page with volatile zero stores, reads every word back, then returns each
claim to the allocator. Inherited loader mappings are not owned or freed.
Old raw aliases are never used after teardown. New user pages are also zeroed
and verified before user permission is installed.

## Proof and limits

The existing three scheduled-user pairs now tear down both roots after thread,
capability and IPC retirement. Each pair returns its fourteen private frames;
42 releases include at least 28 allocations from recycled storage. Available
frame counts return to the same baseline after each pair. The next pair executes
on reused physical storage with fresh private data and intact isolation.

Host tests cover cross-allocator rejection, repeated reuse/count conservation,
bounded metadata exhaustion with claim return, unique outstanding allocations
and reuse-counter exhaustion. A negative hardware image attempts to reclaim the
current CR3 root and must fail before touching any owned page.

This is private address-space teardown, not shared Memory Objects, arbitrary
unmap/shootdown across running CPUs, DMA quiescence, a general heap, or reclaim
policy. Older bootstrap kernel/AP/probe roots remain retained. Process/domain
IDs and capability object/lineage metadata are still retained. Future public
resource operations must turn capacity failures into explicit caller results;
the finite private hardware proof treats broken preconditions as kernel faults.
