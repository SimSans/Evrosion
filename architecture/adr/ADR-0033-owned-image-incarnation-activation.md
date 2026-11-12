# ADR-0033 — Owned-image incarnation activation

Status: Accepted
Date: 2026-10-19
Owners: Project owner; kernel/platform maintainers
Related: ADR-0030, ADR-0031, ADR-0032, INV-AUTH-003, INV-AUTH-007, INV-KERN-005

## Problem and decision

Prepared incarnation tokens and physically loaded executables were verified
separately. A held process still needed an activation transaction that retained
the actual executable backing, rechecked live authority and released admission
without an intervening dispatch or revocation. Teardown also needed to retain
backing until executing threads had stopped.

This Level B refinement adds typed ownership across the existing portable/hardware
boundary and the checked activation transaction. It preserves sealed custody,
single-current-incarnation, exact authority and quiescence-before-replacement
requirements. It does not certify complete BAC ownership, restart or AF-007A–H.
No historical evidence or imported source is changed.

## Hardware ownership contract

`LoadedExecutable` is an unsafe trait with stable process, manifest, entry, stack,
root and frame-count metadata. An implementer must own/retain the actual initialized
page tables and backing, enforce the manifest load plan's W^X/zero-fill/guard
conditions, exclude initialization mutation before admission, and keep physical
backing retained even if the Rust owner is dropped. Reclamation requires a separate
explicit operation proving CPU/mapping/reference quiescence. A plain boolean or
caller-supplied metadata record does not implement this contract.

The real implementation is a private `ProcessImage` exclusive lease over the
`LoadedImage` produced by the existing hardware loader. It prevents mutation or
retirement while the activation record owns that lease. Metadata comes from the
actual root and measured load plan. Lease movement does not copy a large root or
allocate heap storage. The controller retains the owned root slot for the lease's
entire lifetime; dropping a lease never unmaps/recycles frames.

### Narrow lint-policy refinement

The portable library changes `forbid(unsafe_code)` to `deny(unsafe_code)` solely to
allow the annotated unsafe **trait declaration** in `loaded_image.rs`. It performs
no unsafe instructions or memory accesses. All portable implementations remain
safe Rust and inherit deny; the hardware implementation stays in the binary with
its explicit safety argument. Host-only model implementations have individually
annotated exceptions and execute no hardware operations. No module-wide allow was
introduced. This makes the hardware trust obligation explicit and reviewable
instead of hiding it behind a safe readiness callback. Additional exceptions
require the same invariant review; this is not a blanket relaxation of INV-KERN-005.

## Activation transaction

`Bindings::activate` consumes the binding and typed loaded owner. Before changing
the scheduler it checks:

1. The complete token matches the one Bound incarnation.
2. Its actual process remains held, in the expected Job with exact manifest limits.
3. Loaded process/manifest/entry/stack/root/frame-count metadata agrees with the
   measured executable plan; the root is nonzero, aligned and physically bounded.
4. Live custody roots still resolve to the measured canonical authority set.
5. Private branch and user domains contain exactly the recorded handles with current
   generations, no missing, replaced, duplicate or additional grants.
6. Each private branch is a direct descendant of its exact original custody root,
   with exact private rights; each user grant is a direct descendant of that
   branch with exactly the manifest rights. Matching object kind alone is insufficient.
7. The initial Job has one process, one matching Ready thread and the exact charged
   image/stack/page-table frame count.

All fallible work precedes hold release. Exclusive Scheduler and immutable
Authority borrows serialize the commit with dispatch and revocation. Hold release
and construction of the sole `Active` owner complete before these borrows end.
The scheduler release method is crate-private; the hardware consumer cannot bypass
the incarnation gate through a public scheduler release function.

Initial one-process/one-thread admission is an Internal bringup rule, not a product
restriction: additional threads/services may be created under ordinary budgets
after activation. Job totals must not borrow another process's initial frame
charge. Domain/Job/process IDs remain instance-local trusted kernel IDs; the boot
owner must retain the same Authority, Scheduler and unique binding record.

Rejection returns both original owners without releasing admission. Integrity,
measurement or authority failures latch RecoveryRequired; stale event and scheduler
shape failures preserve the held record. Existing charges remain attributed to
the retained image until explicit cleanup. Returning bounded owners by value uses
two documented result-size lint exceptions rather than requiring a heap.

## Stop before reclaim

`Active` privately owns the binding and loaded image lease. It exposes a matching
initial context only while Active. `Active::revoke` validates the token before any
mutation, inhibits future process dispatch (including new/woken siblings), then
revokes the whole private branch group under exclusive scheduler/authority access.
A currently running thread must still return to its controller. Successful removal
enters Revoking; damaged private custody latches recovery and keeps backing retained.

The scheduler records admission release permanently for that process identity.
Inhibition cannot turn a previously admitted process into a fresh bootstrap target.
Ready inhibited threads do not dispatch. Process termination rejects running CPU
slots. `Active::finish` returns the binding and image lease only after matching
revocation and actual scheduler process termination. It returns its owner intact
if teardown is premature. This proves metadata retirement only: the hardware
boundary must still restore CR3, prove CPU/reference quiescence and explicitly
retire/scrub the root before balancing frame charges. Revoked does not authorize
replacement; no reset or next-incarnation operation has been added.

## Verification and scope

Host tests exercise loaded identity fields, stale admission/stop events, exact
authority revalidation, wrong lineage, amplified rights, missing/replaced/extra
handles, frame-charge mismatch, extra/wrong threads or processes, ownership returned
on rejection, stop with a running CPU, inhibited redispatch, premature finish,
damaged custody and refusal to reuse an admitted identity or restart a revoked record.

The kernel integration fixture physically loads two isolated attempts. One passes
the gate, dispatches its actual process/thread, executes the measured ELF at CPL3,
returns via the exact terminal fixture trap, inhibits/revokes and retires. An
unrelated fixture Job remains dispatchable and custody roots remain valid. The
other loses authority after loading and is rejected while held. Both reject a
foreign token and reclaim their nine charged physical frames after controlled
quiescence. The integration proof runs after M1 allocator measurements, preserving
that fixture's starting-pool assumptions. Strict serial/evidence parsers and the
full cumulative regression are required; executed results are linked in
[M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).

These are admitted executable fixtures. The terminal UD2 is a controlled test
boundary, not an automatic Root Supervisor failure/replacement demonstration.
Real supervisor code/bootstrap ABI, trusted generation/epoch production, sealed
singleton ownership, service-graph teardown, restart admission, reusable scheduler
descriptors, IPC/DMA draining and independent recovery remain pending. The current
hardware proof is BSP-only with parked APs and PCID off, not SMP quiescence.
