# ADR-0026 — Bounded restart admission

Status: Accepted
Date: 2026-10-16
Owners: Project owner; kernel/platform maintainers
Related: A-001, E-007, INV-KERN-001, INV-KERN-004, INV-USER-005

## Context

[Root authority custody §13](../designs/ROOT_AUTHORITY_CUSTODY.md) requires a
manifest-defined restart budget and recovery after repeated failure. It suggests
three reconstitutions in sixty seconds but leaves window and failed-spawn
semantics unspecified. A fixed window admits two bursts across its boundary;
counting successful spawns alone permits an unbounded failed-creation loop.

This is a Level B mechanism clarification under the
[engineering direction](../plans/amendments/engineering-direction-2026-10-16.md).
The existing custody design and its recovery guarantees remain in force.

## Decision

Implement an allocation-free sliding-window budget in `kernel/src/restart.rs`.
Accept validated manifest policy with 0–8 attempts and a positive tick window.
Zero attempts disables automatic reconstitution. The three/sixty recommendation
is not hardcoded: conversion from manifest duration to trusted clock ticks is
future integration work. Capacity above eight is rejected, never silently clamped.

Each replacement attempt consumes admission BEFORE creating the replacement,
after old-incarnation revocation and quiescence. Failed creation is not refunded.
Initial boot activation is separate. At most the configured number of attempts
occur in `(now - window, now]`; an attempt expires at its exact deadline.

Exhaustion, a backwards clock or deadline overflow latches a structured recovery
reason. Time passing alone cannot restart a crash loop. The future sealed BAC
must retain the same non-cloneable budget across incarnations, serialize access
and provide trusted monotonic ticks. Construction is trusted boot code, not an
exposed reset operation. Owner-authorized recovery remains possible; this stops
automatic retry, not owner access. A stalled clock still consumes the finite
attempt count. There is no wait or unbounded loop in admission.

## Alternatives considered

- Fixed time buckets: less bookkeeping but allow a double burst at the boundary.
- Token bucket: useful for long-lived throughput; introduces refill/burst policy
  beyond the specified restart-count window and does not itself latch recovery.
- Lifetime attempt count: simple but would escalate rare, widely separated
  failures unnecessarily instead of honoring a rate policy.
- Unlimited timestamp log: exact but unbounded; eight fixed deadline slots
  implement the same admission rule with constant storage and bounded work.

## Invariants preserved

- INV-KERN-001: policy is supplied as data; no service selection or user workflow.
- INV-KERN-004: fixed storage, bounded loops and checked deadline arithmetic.
- INV-USER-005: supplies the restart-limit prerequisite for recoverable services;
  independent recovery and owner-visible explanations still need integration.
- INV-AUTH-007: this module grants no authority. It cannot prove the required
  revocation/quiescence or unique active incarnation; those remain BAC work.

## Consequences and compatibility

No public ABI, persistent format, new dependency or foundational promise changes.
Eight slots bound bootstrap policy capacity and must be reviewed if actual policy
needs more. Conservative clock failure escalates rather than guessing a deadline.
No performance improvement is claimed; tests establish bounded semantics.

This refines previously unspecified semantics, superseding no accepted decision.
The design receives an explicit implementation note; historical imports stay intact.
Removal is a local module reversal before BAC adoption; later changes must retain
the recovery latch and manifest policy guarantees or record a new ADR.

## Verification and review trigger

Host tests exercise failed attempts, exact expiry, cross-boundary bursts, zero and
maximum capacity, malformed policy, clock rollback/overflow and 36,864 exhaustive
small traces against an independent timestamp-history oracle. The cumulative M1
runner checks for regression. See the
[execution record](../../docs/release/0.1-preview.md#validation-and-provenance).

**Not AF-007G acceptance:** no Root Supervisor exists or enters independent
recovery yet. Before BAC integration, verify one budget per boot epoch, immutable
manifest binding, actual fault/creation failures, full subtree quiescence,
bounded metadata reuse and an independent recovery path under QEMU. Full M2
acceptance remains pending.
