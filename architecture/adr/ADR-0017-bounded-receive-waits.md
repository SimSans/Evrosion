# ADR-0017 — Bounded scheduler receive waits

Status: Accepted
Date: 2026-10-02
Owners: Project owner; kernel/platform maintainers
Related: ADR-0011, ADR-0015, ADR-0016, INV-IPC-003–006

## Decision

Add an allocation-free event wait queue with four FIFO registrations. A queue
belongs to one trusted event source and one Scheduler instance. Each entry holds
a generation-bearing scheduler wait ticket, never a userspace thread identifier.
Reaping removes expired or obsolete registrations; an old ticket cannot signal
a later wait. Queue capacity is checked before blocking, so rejection leaves the
current runner intact. No fallible queue mutation follows a successful block.

For bootstrap scalar receives, the IF=0 BSP controller serializes the empty
predicate, wait registration, message enqueue and wake. The interrupt handler
only captures contexts or advances the clock; it does not touch queues. This
prevents a message arriving between the predicate check and registration.
The serialization is a runtime ownership constraint, not an SMP lock design.

The Internal receive-wait operation takes an endpoint handle and a duration of
1–10,000 ticks. Invalid durations and checked-add overflow return failure. The
kernel converts it once into an absolute deadline and retains that deadline in
the blocked call state. Userspace is suspended, so retries cannot extend it.
Successful sends signal the oldest still-blocked receiver. A signal means
readiness, not ownership of a message: the controller checks the original
deadline and retries the capability-authorized receive before user resumption.
Deadline expiry wins at or beyond the boundary, including when signal woke the
thread before expiry but dispatch happened later. An expired call consumes no
queued message or escrow grant. A failed readiness recheck returns explicit
empty/denied status; it does not silently begin a fresh wait.

Scheduler time advances before dispatch and event handling. When no thread is
ready and at least one remains blocked, the controller enables only the owned
timer IRQ and polls for one tick with a finite iteration budget, then disables
interrupts before inspecting runtime state again. A stopped clock reports a
bounded kernel failure. This is bootstrap idle behavior, not a final power policy.

## Verification and limits

Host tests cover capacity rejection without a partial scheduler transition,
FIFO wake, once-only notification, timeout retirement, stale-generation reuse,
deadline/CPU errors and bounded duration decoding. QEMU runs the existing three
process pairs with real blocking receives: three arrival wakes, three timeout
wakes, and no surviving registrations or pending calls. The sender checks a
fixture-only blocked-state diagnostic before sending, ensuring the signal test
actually exercises a blocked receiver. Timeout progresses with no runnable user
thread. The peers still prove capability attenuation and ordinary fault survival.

A separate image masks IRQ0 specifically during blocked-user idle; 4,096 polls
must end in the expected failure, never a hang or a successful boot marker.
The prior CPL0-fault and kernel-context failure fixtures remain required.

The four-waiter policy is host-tested; hardware integration currently has one
receiver per endpoint. All process resources remain retained. Explicit wait
cancellation, process-wide termination, peer-death subscriptions/queue cleanup,
sync-call ancestry, shared-memory transfer, resource charging, arbitrary program
contexts and SMP scheduling remain pending. This does not complete M1 or 0.1.
