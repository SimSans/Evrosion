# ADR-0011 — Bounded scheduler state and Job attribution

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-025.23, PRE-M0 §43, R-011.14

## Decision

Introduce an Internal, allocation-free scheduler state machine with fixed bounds
of 8 Jobs, 16 Processes, 32 Threads and 8 logical CPU slots. A thread belongs to
one Process and that Process belongs to one Job. Retain all slots, including
exited threads, during this bootstrap lifetime. Typed indices are trusted
instance-local kernel handles, not capabilities or public object identities.

A single mutable owner serializes dispatch, yield, block, signal, timeout and
exit transitions. Round-robin dispatch inspects at most 32 slots, selects only
ready threads and prevents double dispatch to occupied logical CPU slots. This
is fairness across continuously ready threads when the caller returns control,
not wall-clock fairness or preemption. Charge successful dispatch counts to the
owning Job, with checked arithmetic and no partial mutation on overflow. Counts
are not elapsed CPU time, budget enforcement or complete Job accounting.

Every blocked state carries an absolute finite monotonic deadline and a unique
nonwrapping wait generation. Signals succeed once for that wait; stale tickets
cannot wake later waits. Advancing time scans at most 32 slots and rejects time
reversal. At the integration boundary, update time before processing signals;
timeout then wins at the exact deadline. Predicate checks and wait registration
must share serialization with event production; this state machine alone does
not provide a lost-wakeup-safe IPC/event queue.

## Staging and limits

The first proof executes scheduling decisions on the BSP's existing boot stack,
after the AP startup fixture parks. Its two logical thread records do not have
independent hardware contexts yet. CPU slots exercise exclusivity in host tests;
they do not establish concurrent SMP scheduling. No IRQ is enabled and no new
unsafe code is introduced. Fixed bootstrap capacities are not promised product
limits. Instances must not exchange handles. Slot reuse and external handles
need generation/authority validation before capability integration.

Next, add retained thread stacks and audited context switching, then connect
timer preemption, per-CPU serialization, process roots and general fault delivery.
M1-04 remains ACTIVE until actual threads progress and the integrated wait/wake
and ownership proofs pass. RES-003 complementary acceptance confirmation remains
required before the final M1 checklist is finalized.

## Verification

Host tests cover full-queue fairness, owner attribution, CPU exclusivity,
blocked/exit exclusion, finite exact-boundary timeout, once-only/stale wakeups,
capacity, invalid transitions, time reversal and atomic overflow rejection.
Repeated real QEMU boots execute a finite 36-dispatch policy fixture, checking
two Jobs, explicit signal and deadline wakeups, stale rejection and final idle.
The protocol identifies `scope=policy`; it must not be interpreted as a hardware
context-switch proof. Existing boot, isolation, timer, AP and failure regressions
remain in the cumulative acceptance script.
