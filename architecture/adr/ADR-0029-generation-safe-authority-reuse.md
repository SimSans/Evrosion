# ADR-0029 — Generation-safe authority-domain and lineage reuse

Status: Accepted
Date: 2026-10-18
Owners: Project owner; kernel/platform maintainers
Related: ADR-0014, ADR-0018, ADR-0028, INV-AUTH-003, INV-AUTH-007, INV-KERN-004

## Context and scoped supersession

M1 deliberately retained every authority-domain identity and lineage node. The
eight-domain/32-node limits would stop repeated supervisor binding despite no
remaining users of those particular records. Merely resetting tables would revive
stale identities or sever revocation ancestry.

This Level B decision **supersedes ADR-0014's permanent retention of closed
authority-domain slots and unreachable lineage nodes only**. Original M1 evidence
and imported plans remain unchanged. Object descriptors, scheduler identities and
physical resources remain retained or governed by their existing lifetime rules.
This decision does not certify full process restart or change any OS guarantee.

## Domain reuse

SpaceId now contains slot and u64 generation. Every lookup and close validates both.
`create_space` still allocates unused slots and never silently recycles. After
explicit closure, the trusted lifecycle owner may call `recycle_space` once all
external process/mapping/IPC teardown obligations have been handled. It increments
the generation with checked arithmetic, preserves capability-slot generations and
returns a new identity. A live space cannot be recycled. Exhaustion leaves the old
space closed; it never wraps to a previous identity.

SpaceIds remain trusted, Authority-instance-local kernel IDs, not userspace
capabilities or cross-instance handles. The trusted caller must use the correct
Authority instance as before. Existing IPC sender/receiver comparisons include the
new generation, preventing an occupant of a reused slot from reclaiming old escrow.

## Lineage collection

`collect_lineage` is an explicit, allocation-free mark/sweep over the bounded table.
Every handle in every capability table, including private mailbox escrow, marks
its complete parent chain. Keep reachable nodes even when revoked or when their
intermediate handles have closed. Sweep only unmarked nodes, after all traversals
finish successfully. A missing parent or cycle rejects collection before mutation.
At most 64 handles × 32 ancestry steps plus 32 sweep slots are visited.

Parent indices are safe without node generations only because all live references
are table handles or retained parent links, and their complete ancestry is marked.
Borrowed Access values exclude collection through Rust borrowing. Raw diagnostic
indices are not ownership. Any future detached revocation token or cached node
reference must pin ancestry or use non-repeating node generations before it can
survive collection. That is a mandatory integration constraint for BAC work.

Existing generation-checked table handles protect against a freed node being reused
by a later grant. Objects are never recycled by this operation, so live Memory
Object/endpoint bindings cannot silently alias a different object descriptor.

## Alternatives and tradeoffs

- Increase capacities: delays exhaustion without solving lifetime.
- Reuse the same SpaceId: permits old messages/IDs to name the replacement owner.
- Free nodes when their handle closes: destroys ancestry needed by delegated leaves.
- Add reference counting everywhere: adds mutation/error paths to every transfer;
  a bounded explicit scan is simpler at current capacities.

The scan has a fixed upper bound and is outside interrupt handling. It is not a
claim of production-scale collector performance. Explicit rather than automatic
collection keeps existing M1 paths unchanged. Review the approach when table sizes,
concurrency or detached lineage references change. No public ABI or stable format
changes; SpaceId is an Internal trusted-kernel type.

## Verification and limits

Tests prove old IDs/handles fail after reuse, exhaustion stays closed, ancestor
revocation survives intermediate closure, cyclic corruption fails before sweeping,
512 repeated host batch cycles exceed both old capacities, and an in-flight escrow
grant survives collection while a recycled sender cannot reclaim it.

The kernel fixture repeats 64 measured binding/retirement cycles, reclaims exactly
128 descendants, preserves the expected custody digest and rejects old identities
while new grants are live. Strict boot-protocol and M2 evidence parsers check the
record; the cumulative regression remains required. Evidence is linked from
M2 progress.

These are authority-metadata proofs, not repeated executable-process recovery.
Descriptor reuse, scheduler reuse, sealed custody, incarnation-wide revocation,
actual quiescence and independent recovery still require implementation and tests.
