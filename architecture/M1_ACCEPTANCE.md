# M1 acceptance contract

Status: PASS — verified 2026-10-03.
Aggregate evidence (local engineering archive) and
readiness/limits.
Scope: the owner-confirmed union of E-025.18–23, PRE-M0 §43 and R-011.14.
Run `python3 tools/m1/acceptance.py` for the complete mechanism gate.

## Required mechanisms and evidence

The cumulative runner executes each earlier mechanism and validates strict serial
records, repeated fresh boots, host boundary tests and negative images. These
links identify the executed prerequisite proofs; the aggregate record above
contains the final gate and refreshed regression snapshot.

| Required behavior | Executed evidence |
|---|---|
| Validated boot handoff and observable diagnostics | Frozen M0 acceptance (local engineering archive) plus all cumulative M1 boots |
| Physical page allocation and kernel allocation after bootstrap | Frame ownership/recycling (local engineering archive), dynamic allocations during user execution (local engineering archive) |
| Create multiple isolated address spaces; map/unmap and anonymous memory | CPL3 isolation (local engineering archive), allocation/free and stale-address faults (local engineering archive) |
| Threads, basic scheduling, saved CPU state | Guarded contexts (local engineering archive), preemption (local engineering archive), user extended state (local engineering archive) |
| Exceptions, interrupts and timers | Protection faults (local engineering archive), bounded timer (local engineering archive) |
| Early SMP without uniprocessor data-model assumptions | Actual second CPU and shared atomic work (local engineering archive), scheduler CPU slots and exclusive-owner boundaries |
| Object capabilities, derivation and revocation | Authority tables (local engineering archive), hardware mapping revocation (local engineering archive) |
| IPC endpoint/control transfer and capability transfer | Bounded mailbox/escrow (local engineering archive), actual scheduled-user IPC (local engineering archive) |
| Bounded wait/wake | Arrival, deadline, stale ticket and stopped-clock proofs (local engineering archive) |
| Shared Memory Objects | Capability-checked hardware sharing (local engineering archive), lease invalidation (local engineering archive) |
| Fault delivery and ordinary user-fault survival | Actual UD/PF/GP notification and survivors (local engineering archive) |
| Quiescent teardown and ownership return | Process/escrow retirement (local engineering archive), scrubbed physical reuse (local engineering archive) |
| Job skeleton and resource attribution | Hierarchical admission/accounting (local engineering archive), runtime allocation rollback (local engineering archive) |
| AF-003: no capability means denial | Host owner/generation/type/rights checks and real invalid endpoint, allocation and mapping calls in the cumulative suite |
| AF-005: attenuation cannot regain rights | Host derivation/transfer tests and actual receiver WRITE denial while READ succeeds |
| AF-009: Memory Object requires capability | Host `af009_mapping_requires_right_object_map_and_access_rights` plus actual unauthorized map/allocation denial |

## Deliberate initial limits and M2 handoff

M1 is the minimum kernel spine, not a general application environment. Its
Internal scalar calls run bounded built-in user programs; metadata slots are
finite and retained, while actual memory frames recycle. It supplies page-based
kernel allocation after bootstrap without introducing an unneeded general heap.
Job CPU accounting samples user timer ticks; it is not precise elapsed CPU time
or a replenishing resource-policy service.

The AP executes independently and proves shared atomic work, then parks before
BSP userspace. Address-space mutation is serialized with interrupts disabled;
roots are inactive and no AP uses them. Concurrent user scheduling, AP interrupt
recovery, APIC timer routing and remote TLB shootdown must be added together before
relaxing that restriction. User x87/SSE state is isolated; AVX/XSAVE and FSGSBASE
remain disabled, and there is no TLS ABI.

M1 requires an IPC primitive. Its asynchronous mailbox and real block/wake meet
that requirement. Synchronous typed RPC, causal ancestry/cycle detection and
AF-IPC-001–010 are part of the M1/M2 discipline design and remain M2 work before
exposing synchronous RPC. No synchronous API is exposed by M1. The working plan's
earlier mention of sync IPC as unfinished did not distinguish this minimum gate
from the complete M1/M2 design; this contract makes that boundary explicit.

PRE-M0 §43 explicitly assigns Root Supervisor to M2; R-011.15 assigns custody and
restart semantics there. M1 keeps private kernel root custody and quiescent
revocation/lifetime primitives. Bootstrap Manifest validation, BAC incarnation
reconstitution and AF-007A–H remain mandatory M2 work. No service graph is pulled
into M1 and no later fitness result is inferred from these mechanism proofs.

## Revision and evidence boundaries

M0 stays frozen at `m0`. Its historical evidence is not rewritten. The owner's
working tree includes uncommitted dependency changes, so the existing doctor and
clean-clone reproducibility commands correctly reject that revision state.
A source-matched isolated committed test snapshot inside `build/m1/` can run the
unchanged full M0 regression and clean-clone comparison without committing the
owner's branch or bypassing either check. Its source manifest and revision must
be recorded. That is a local verification snapshot, not a release or remote CI
run; the working branch still needs owner review before GitHub publication.
