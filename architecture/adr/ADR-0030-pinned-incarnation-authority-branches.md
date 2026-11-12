# ADR-0030 — Pinned incarnation authority branches

Status: Accepted
Date: 2026-10-18
Owners: Project owner; kernel/platform maintainers
Related: ADR-0014, ADR-0028, ADR-0029, INV-AUTH-003, INV-AUTH-007

## Problem and scoped refinement

Direct bootstrap grants descend from permanent custody roots. Revoking those
roots would also prevent replacement; closing the supervisor's local handles
would leave transferred and delegated authority alive. A detached raw node index
could alias a new node after ADR-0029 collection.

This Level B decision refines the single incarnation revocation node described
in ROOT_AUTHORITY_CUSTODY §9.3/§10.2 into a bounded, atomically revoked group of
per-object branches. It preserves the same all-descendant invalidation guarantee.
This is SUP-013; the scoped mechanism refinement preserves the imported technical
requirements and does not revise historical evidence.
One ACTIVE incarnation, revocation before replacement, actual quiescence and
independent recovery remain mandatory. None is satisfied merely by this primitive.

## Mechanism

Each existing capability node belongs to one object and one parent. Instead of
adding cross-object parent semantics throughout capability lookup, derive a
private branch from each manifest-selected custody root, then derive the exact
requested user grant beneath that branch. A kernel-only domain pins all branches
using ordinary generation-checked handles. No bare node identity escapes.

`derive_scoped_into_empty` preflights both empty destination domains, all source
rights, every slot generation and all 2N lineage nodes before changing anything.
Both domains must differ from custody and from each other. At most eight objects
consume sixteen nodes. The shared transaction implementation retains direct
single-level binding for existing fixtures. Failure consumes no generation or
metadata and leaves both destinations empty.

Private branches contain the requested rights plus DERIVE, TRANSFER and REVOKE;
the original custody roots must authorize all of them. Users receive exactly the
manifest rights, never these additional private rights. The branch domain and its
handles must never be exposed through a userspace interface. This Internal API
does not yet enforce sealed BAC ownership at the runtime boundary.

`install_scoped` shares live selector/measurement validation with ADR-0028. Its
authority-set digest still includes the original custody roots, so transient
branch identities do not change the canonical set across replacement attempts.
Boot epoch, counter, process and Job identity must be bound separately by the BAC.

`revoke_batch` checks every local handle generation and REVOKE right before any
mutation, then marks all branches invalid under the exclusive Authority borrow.
Already revoked ancestry or dead objects do not obstruct this authority-removing
operation. Repeated teardown succeeds while the private handles remain present;
stale domain generations or stale handles fail before any new branch is touched.
All lookups and transfers use the same serialization domain, so they either
complete before revocation and become invalid, or fail after it. This is not a
multi-CPU scheduler/concurrency proof.

Collection retains private branches even after all user handles close, and retains
revoked ancestry while any delegated or escrow handle still references it. Branch
closure/recycling belongs after external teardown. Revocation does not itself
unmap pages, drain DMA, stop threads, destroy objects or certify quiescence.
Domain IDs remain Authority-instance-local trusted kernel values as in ADR-0029.

## Alternatives and limits

Revoking permanent roots breaks recovery. Closing local user handles misses
delegated descendants. Detached node indices are unsafe across collection. A new
cross-object lineage-group type could work but adds a second parent relation and
collector rules; pinned per-object branches reuse already verified semantics at
the cost of one private domain and N additional nodes per attempted incarnation.
If these bounded capacities become inadequate, revise the allocation mechanism
explicitly without weakening group revocation or stale-event rejection.

## Validation

Host tests cover atomic capacity/generation/rights failures, exact attenuation,
delegated and moved descendants, queued escrow revocation, transfer on either side
of revocation, root/peer survival, idempotence, digest equality and 512 branch-domain
reuse cycles with stale teardown attempts against live replacements.

The kernel fixture runs 64 scoped binding/revocation cycles, checks both grants
fail while custody and an unrelated grant remain live, collects each level only
after its handles close and rejects stale teardown handles. Strict boot/evidence
parsers reject missing, duplicate, out-of-order and malformed records. Executed
results are recorded in [M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance).
The fixture image remains `abc`; it launches no Root Supervisor. Full incarnation
tokens, scheduler integration and AF-007A–H remain pending.
