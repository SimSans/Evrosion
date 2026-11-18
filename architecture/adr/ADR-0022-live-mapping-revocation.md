# ADR-0022 — Live mapping revocation before user dispatch

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0014, ADR-0020, INV-AUTH-002

## Decision

A shared mapping lease retains its original authority domain and grant handle.
The serialized BSP controller returns to the retained kernel root on every user
trap. Before dispatch it validates every live lease against the capability table.
Revoked grants and closed domains lose their hardware leaf and lease while their
root is inactive. The next CR3 load invalidates stale translations; these roots
use neither PCID nor global user leaves, and no AP executes them.

Revocation does not destroy independently authorized sibling grants or backing
still held by another mapping. Object destruction still requires zero leases.
The original handle must retain the mapping's READ/MAP and, when writable, WRITE
rights. A subsequent attempted map through a revoked grant fails normally.

## Verification and limits

Host tests validate lease invalidation and destruction ordering. Three real user
revocations remove existing mappings. Exact CPL3 probes at the old address must
raise a nonpresent read page fault; remapping is denied and sibling READ remains
usable. Cumulative normal, two-CPU, negative-image and debugger proofs are linked
in portable evidence (local engineering archive).

This is serialized revocation with parked APs, not a remote TLB shootdown protocol.
Concurrent execution of these address spaces must add a quiescence/shootdown
mechanism before relaxing this ownership boundary.
