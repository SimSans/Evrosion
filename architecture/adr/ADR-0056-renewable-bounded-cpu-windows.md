# ADR-0056 — Renewable bounded CPU windows

Status: Accepted implementation refinement; runtime integration and physical verification pending.
Date: 2026-11-12.
Owners: Project owner; kernel/runtime maintainers.
Related: E-004; E-023.4/45; M6-02; ADR-0011; ADR-0021; ADR-0051.

## Decision

Add an explicit, trusted, one-time CPU-window configuration to the existing
Scheduler Job. This is a Level B implementation refinement under the engineering
mandate. No userspace policy, syscall, unguarded limit mutation or new resource
ownership hierarchy enters the kernel. Existing all-finite M0–M5 schedulers keep
their lifetime CPU limits and existing dispatch/charging semantics.

An interactive runtime may configure a never-dispatched Job with a nonzero,
finite quota and period. Quota must not exceed the period or the Job's declared
CPU limit. That limit becomes the ceiling for this explicitly selected periodic
contract, rather than a lifetime cap. Frame, process and thread limits retain
their existing meaning. `usage(CpuTicks)` remains checked cumulative sampled CPU
consumption, charged to the owning Job and every ancestor, and never resets when
a window renews or a child is retired/recreated. Overflow fails closed.

The first opt-in requires all CPU contexts returned to their controller. Later
new children may be configured while unrelated actors run. Neither a configured
Job nor an already-dispatched subtree can be reconfigured to recover credit.
Dispatch records this fact at every ancestor, including legacy executions that
finish before a sampled tick. Reaping that descendant cannot erase the surviving
ancestor's execution history; direct per-Job dispatch counters keep their meaning.
Job handles retain the same slot/generation validation. Diagnostic snapshots are
copies, not authority. Reclaiming a child does not refund its ancestors' CPU use
or current-period credit. Persistent workload quotas should be placed at a
surviving owner Job when policy must survive replacement of subordinate Jobs.

## Time and reservations

The sole trusted owner advances the Scheduler using actual monotonic capture
time before dispatch/accounting and wake processing. Reversed time fails before
mutation. At an exact period boundary the window allowance renews; skipped
periods accumulate no credit. Next-boundary arithmetic is checked before any
window renewal, clock change or timeout wake. An unrepresentable future boundary
fails closed instead of wrapping or introducing an infinite sentinel.

After opt-in, dispatch reserves one sampled CPU tick at the selected Job and
every ancestor, including any finite ancestor. All reservations are preflighted
before dispatch changes state. Exhausted candidates remain Ready and are skipped;
other eligible Jobs remain schedulable. Concurrent CPU records cannot consume
one another's last credit. An actual timer charge consumes the reservation and
updates all cumulative/window counters atomically. A nonblocking syscall retains
its reservation; yield, block and exit release unused credit. A trusted owner
continuing a Running context after charging must first reacquire credit through
`reserve_cpu`. The present intended hardware integration charges one sampled
tick per timer capture. Batched accounting must fit available credit and cannot
take another CPU's reserved allowance.

Outstanding reservations survive a window boundary and reduce the new window's
available credit. This deliberately avoids granting the same already-running
quantum twice. It is a bounded sampled-accounting mechanism, not exact elapsed
CPU time, hard real-time scheduling, CPU-frequency control or physical SMP proof.

Quotas are upper bounds, not guaranteed/reserved QoS entitlements. Oversubscribed
children still share their parent's cap. Runtime policy must leave headroom for
critical services and keep interrupt preemption active. CPU exhaustion is not
thread exit, permission to reclaim buffers, or a general recovery receipt.

## Runtime and observability obligations

M6's separate interactive profile must configure its boot/Root/service workload
owners appropriately; a remaining finite ancestor still enforces its lifetime
cap. The runtime must handle an empty dispatch result by bounded interruptible
idle until time or another event can make work eligible. This module neither
enables interrupts nor performs context switches. Operation deadlines, health
probation, restart limits and resource-retirement rules remain independent.

Budget-aware diagnostics must distinguish cumulative usage from the quota,
current window consumption, reserved ticks and remaining allowance returned by
`cpu_budget`. For an opted Job, cumulative CPU usage may exceed the old scalar
CPU-limit field; presenting that field as a lifetime limit would be misleading.
No existing Internal userspace wire contract is silently relabelled by this ADR.

## Validation boundary

Focused host tests exercise repeated renewal beyond lifetime ceilings, exact
boundaries, skipped periods, reservation ownership across CPU records, parent
and sibling pressure, fixed/periodic mixtures, one-time configuration, child
replacement, stale generations, retained staged copies, time reversal and
arithmetic exhaustion. Refusal must preserve the complete scheduler state.
Existing kernel tests must continue to pass.

This record establishes no sustained interactive or hardware acceptance.
Source-pinned target/stack checks and actual M6 execution must subsequently show
long-lived legitimate work beyond the old finite bounds, containment of an
abusive app, accurate accounting and clean retirement. M0–M5 finite profiles
retain their existing claims and limits.
