# M1 — Kernel Spine working plan

Started: 2026-09-30
Status: PASS — integrated acceptance verified 2026-10-03. Physical reclamation, anonymous
allocation, shared Memory Objects, live revocation, extended CPU contexts,
hierarchical Job accounting and capability-routed fault delivery now join the
verified bootstrap, scheduling and IPC primitives.
See executed progress and the
[complete acceptance contract](M1_ACCEPTANCE.md) for the M1/M2 boundary.

## Scope and baseline

M1 implements the kernel spine within the M1–M5 developer-preview scope.
The specific architecture decisions below retain their recorded boundaries.
Engineering acceptance and public release are separate decisions.

M0 remains accepted and frozen at tag `m0`. Its existing evidence stays intact.

At M1 start the kernel validated the boot handoff, printed bounded diagnostics
and halted/exited. The implementation now runs isolated, preempted user contexts,
capability IPC, runtime allocation and ordinary process fault retirement. The
memory map distinguishes usable and reserved ranges; the adapter checks that the
kernel image is reserved. The final aggregate acceptance is linked from the acceptance contract.

## Ordered slices and acceptance

| Slice | Work | Required proof before completion |
|---|---|---|
| M1-01 — Physical memory | Owned aligned frames, exhaustion, scrubbed reuse | Linked allocator/reclamation proofs |
| M1-02 — Address spaces and memory | Private roots, anonymous allocation, shared objects, map/unmap | CPL3 isolation, zeroed reuse, freed/revoked-address faults |
| M1-03 — Exceptions, interrupts and time | Protection entry, timer, bounded waits, actual AP startup | Exact fault checks, stopped-clock/withheld-AP negative images |
| M1-04 — Threads and scheduling | Kernel/user contexts, preemption, x87/SSE state, hierarchical Jobs | Independent progress, state corruption rejection, balanced resource attribution |
| M1-05 — Objects and capabilities | Attenuation, transfer, revocation, live-map invalidation and custody primitives | AF-003/005/009, stale denial and quiescent backing destruction |
| M1-06 — IPC and fault delivery | Bounded mailbox/escrow, receive wake, fault notification and retirement | Actual CPL3 messages, once-only diagnostics, peer survival and cleanup |
| M1-07 — Integrated acceptance | Complete cumulative gate and source-matched regression snapshot | All prerequisite checks, governance and recorded evidence before PASS |

The order expresses dependencies, not a requirement to finish an entire subsystem
before designing its interfaces. Object ownership and authority must shape memory
and scheduling from the start. Internal bootstrap frame ownership is not a public
capability or userspace memory API. Reusable allocation, zeroing, page-table safety
and synchronization remain required later in M1 even if the first bootstrap
allocator only hands out frames monotonically.

## First slice boundary

Implemented a small allocation-free bootstrap frame allocator in `kernel/`, consuming
Evrosion's validated boot-contract types. Keep its portable logic host-testable.
Initially it runs during boot with interrupts disabled and one mutable owner;
this is a lifecycle restriction, not an assumption that Evrosion is uniprocessor.
No frame is mapped, dereferenced or exposed to a user process by this first slice.
Do not reclaim loader/reserved memory. Keep temporary loader types inside the
existing adapter and review EXC-0001 before any scope expansion.

[ADR-0004](adr/ADR-0004-m1-bootstrap-frames.md) records the privileged-kernel decision.
Tests must distinguish frame selection from actual page mapping and memory
isolation; the first cannot be claimed as proof of the latter. No interface moves
beyond Internal maturity in this slice.

## Open decisions

- **RES-002 — resolved 2026-09-30:** retain E-025.23's ordinary user-process fault
  survival proof at M1 exit. After the recommendation to prove containment in M1
  while leaving service supervision/restart to M2, the owner replied “ok go then”.
  PRE-M0 §36's later AF-002 timing does not postpone that M1 exit proof. The source
  documents remain preserved; this decision does not claim containment implemented.
- **RES-003 — resolved 2026-10-02:** use the full combined M1 scope from
  E-025.18–23, PRE-M0 §43 and R-011.14, including the Job/accounting skeleton,
  capability derivation/revocation and architecture fitness tests. The owner
  confirmed that final acceptance should include this combined scope.
  This resolved scope; implementation and acceptance were verified separately in the subsequent M1 gate.
- **OQ-7 — SMP implementation plan, 2026-10-01:** bootstrap began on one CPU
  (E-025.21). The implementation plan selected a two-CPU M1 proof before the
  scheduler/locking design was fixed. This was an implementation choice within
  the selected scope, not a separately selected owner answer.

No filesystem, networking, desktop UI, Windows runtime or userspace memory policy
is added to the kernel. Existing later product requirements remain in their
assigned milestones.

## Sources

- [E-002 kernel boundary](plans/core/E-002-kernel-architecture.txt)
- [E-005 memory mechanisms and policy](plans/core/E-005-memory-architecture.txt)
- [E-025 §18–§23 scope and exit criteria](plans/roadmap/E-025-initial-scope.md)
- [PRE-M0 §36 and §43](plans/roadmap/PRE-M0-implementation-package-v1.md)
- [R-011.14](plans/release-project/Evrosion_R-007_to_R-011_Superfile_v1.md)
- [Authority custody](designs/ROOT_AUTHORITY_CUSTODY.md), [IPC discipline](designs/IPC_DISCIPLINE.md)
