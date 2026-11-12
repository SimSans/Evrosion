# ADR-0025 — Capability-bound anonymous allocation

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0019, ADR-0020, ADR-0021, E-025.22

## Decision

Bind an Internal allocator capability to an existing process protection domain
and its Job. A request checks caller, object kind, identity and CONTROL before
charging one frame through the complete Job ancestry. Physical exhaustion,
object capacity or destination-table failure returns the frame and charge.
Retained descriptor/lineage metadata remains bounded and can itself exhaust;
failed allocations do not promise reclamation of that metadata.

Anonymous backing is a one-page Memory Object. A kernel custodian retains its
root; the caller receives READ/WRITE/MAP/CONTROL with no delegation or revocation
right. Hardware setup zeroes every byte before returning the grant or address.
The bootstrap user root supports two independently owned non-executable leases,
allowing private anonymous memory alongside a shared IPC page.

Free checks the exact issued handle and CONTROL, removes the inactive-root leaf,
returns its lease, destroys the descriptor, closes handles, scrubs backing and
returns its physical claim and Job charge. Process retirement uses the same
kernel custody path even if the user's authority domain is closing. There is one
outstanding anonymous allocation per process in this Internal API; requests have
explicit denial/capacity returns. This is basic userspace allocation support,
not a general heap, permanent ABI or userspace memory-policy service.

## Verification

The cumulative allocation runner tests six real user allocate/use/free cycles,
whole-page zeroing after writing nonzero bytes, duplicate/stale free denial and
six exact CPL3 page faults at freed addresses. Job evidence accounts for the 45
initial frame claims plus six dynamic claims; live counts return to zero.
Portable tests cover authority, budget, physical exhaustion, descriptor capacity
and failure after object creation when the receiver table is full. Linked
execution evidence is required before marking this slice PASS.
