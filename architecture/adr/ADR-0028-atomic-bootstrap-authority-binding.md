# ADR-0028 — Atomic bootstrap authority binding

Status: Accepted
Date: 2026-10-18
Owners: Project owner; kernel/platform maintainers
Related: A-001, ADR-0027, INV-AUTH-002, INV-AUTH-003, INV-AUTH-007

## Decision and reason

Manifest measurement alone does not prove that a selector resolves to the right
live object. Installing grants incrementally could leave a partial authority set
after a late mismatch or capacity failure. Add a bounded resolver and transactional
derivation to the existing authority mechanism. This is a Level B refinement under
the accepted engineering direction, preserving the [custody design](../designs/ROOT_AUTHORITY_CUSTODY.md).

`bootstrap_binding::install` holds exclusive access to the authority tables across
catalog validation, live authorization, canonical set hashing and batch installation.
It requires 1–8 strictly sorted, distinct catalog selectors, distinct live object
identities and original root nodes with DERIVE and TRANSFER. Every requested kind
and right must independently pass actual capability authorization. A selector,
diagnostic identity or manifest declaration is never sufficient authority.

Reject range-constrained Memory grants at binding for now: the existing runtime
cannot enforce sub-object extents. Parsing remains supported by ADR-0027, but
activation cannot silently strip those constraints. Whole-object grants are the
only implemented activation subset. No claimed product guarantee is weakened.

## Canonical authority digest

SHA-256 input is the bytes `evrosion.bootstrap.authority.v1` followed by a NUL,
then grant count as little-endian u64, followed in manifest selector order by:

- selector u64;
- actual object kind u8 (the ADR-0027 explicit mapping);
- actual object identity u64 and original custody-lineage root identity u64;
- requested rights u16;
- constraint tag u8 (0 for whole object), start u64 and length u64 (both zero).

Object and lineage identities are independently obtained from live authorization.
They are stable within the current retained-table boot lifetime. Expected digests
therefore bind the trusted boot catalog's deterministic allocation layout; they
must not be guessed from mutable runtime handles. When identities become reusable,
the binding must include their non-repeating generations or stable custody IDs.

The digest names stable custody roots, **not newly created descendant nodes or
incarnation numbers**. Reconstitution must reproduce this same authority set while
the incarnation token separately binds epoch/number/process/Job/manifest. This
clarifies the existing design's equal-set requirement across incarnations; it does
not waive incarnation-scoped revocation or authorize two active supervisors.

## Atomic installation

`Authority::derive_into_empty` requires an empty, distinct destination. Preflight
every source, requested kind/right, destination generation and free lineage node
before mutation. Then install all descendants in an infallible bounded commit.
Exclusive mutation provides the current serialization boundary. No rollback is
needed because all failures occur before commit; failed admission consumes no
node or generation. The original custody handles remain intact.

Do not schedule the destination merely because this primitive succeeded. Sealed
BAC ownership, executable selection/loading, incarnation binding, group revocation,
quiescence and resource teardown remain required. M1's retained metadata is still
finite; exhaustion denies the entire operation, never partially installs authority.

## Alternatives and tradeoffs

- Hash only selectors: fails to detect substitution with a different live object.
- Install then roll back: increases the number of failure states and can leak
  metadata or permit accidental scheduling of a partial table.
- Clone whole tables: adds stack/storage and unnecessary object-lifetime coupling.
- Ignore unsupported constraints: grants more authority than the manifest permits.

No public ABI or persistent format is promoted. Existing scalar derivation remains
compatible. No accepted decision is superseded; ADR-0027's parser retains its scope.
Review this implementation before reusable object identity, concurrent dispatch or
the full BAC is introduced. Full supervision remains an uncompleted M2 gate.

## Verification

Host tests cover late rights/kind failure, destination contamination, generation
and node exhaustion, source revocation, alias/branch rejection, object substitution,
digest mismatch and successful retry without leaked authority. An independently
encoded binary fixture fixes the exact hash representation.

The kernel executes measurement and binding against actual authority tables during
normal boots: substituted catalog rejection leaves the destination usable for the
correct batch, WRITE remains denied, root revocation invalidates its READ descendant
and the unrelated endpoint survives. The image is deliberately a digest fixture,
not a supervisor executable. `python3 tools/m2/binding.py` checks exact proof markers
on repeated one/two-CPU boots and includes the complete M1 regression. See
[M2 progress](../../docs/release/0.1-preview.md#validation-and-provenance) for executed evidence.
