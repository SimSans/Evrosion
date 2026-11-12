# ADR-0013 — Bootstrap timer preemption

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-002, E-025.23, ADR-0008, ADR-0011, ADR-0012

## Decision

Reopen the initialized BSP PIC/PIT IRQ0 clock for a bounded kernel-thread proof.
Use the guarded stack construction and cooperative switch boundary from ADR-0012.
An IRQ saves the entire interrupted GP register frame before Rust entry. After
acknowledging IRQ0 and releasing the exception recursion guard, the active
preemption hook saves the interrupt continuation on its worker's private stack
and returns to the controller with IF=0. The controller serializes Scheduler
transitions and dispatches the next ready worker. Resumption completes the old
interrupt handler and IRET restores the worker's interrupted state and IF.

Only workers enable IF. The controller and all scheduler mutations run with
IF=0; APs remain parked. Suspended trap frames occupy distinct retained worker
stacks. No global context reference spans a switch. Double fault/NMI retain
separate IST stacks and fatal handling. This does not permit scheduling from an
arbitrary fault, nested handler, or critical section.

The two finite workers never voluntarily yield while doing work. Each receives
at least four timer interruptions, retains private stack data and then exits.
Timer ticks, per-thread quanta and owning Job dispatch counts must agree. Counts
measure timer events and dispatches, not precise elapsed CPU time or enforced
Job budgets. Preserve monotonic ticks across the earlier timer proof.

## Verification and bounds

Run cumulative one/two-CPU boots and debugger checks. Require both workers to
make progress, at least eight total quanta, complete exit, and exactly one more
dispatch than timer interruptions for each Job. Bound the controller loop and
worker iteration counts. A masked-clock image gives the worker 4096 iterations
and requires its explicit finite-failure diagnostic and QEMU failure exit.

## Limits

This is BSP kernel preemption on Q35 PIC/PIT, not userspace/SMP scheduling,
APIC timer support, arbitrary device routing, accurate CPU-time budgets or an
unbounded runtime. Per-process TSS/root/lifetime, event queues and fault delivery
must be integrated before M1 exit. The existing general unexpected-fault path
remains fatal; no arbitrary user fault is claimed contained by this proof.
