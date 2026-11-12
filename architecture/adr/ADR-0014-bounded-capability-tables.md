# ADR-0014 — Bounded capability tables and retained derivation

Status: Accepted
Date: 2026-10-01
Owners: Project owner; kernel/platform maintainers
Related: E-009.6–E-009.10, E-025.23, ROOT_AUTHORITY_CUSTODY

## Decision

Introduce allocation-free Internal authority tables: four trusted protection
spaces, eight slots per space, eight object descriptors and 32 retained lineage
nodes. Caller identity comes from a trusted kernel space, never a raw user
argument. Handles contain a slot and a nonzero, nonwrapping generation. Numeric
handle equality across different spaces does not imply shared authority.

Every authorization validates the owner table, generation, live object, object
class, requested rights and every ancestor in a bounded lineage walk. A borrowed
Access keeps the table immutable during an operation; copied diagnostic object
identity is not a grant. Mutations require one exclusive owner. Real operations
must retain authorization through their serialized commit boundary.

Derivation requires DERIVE; cross-space delegation additionally requires TRANSFER.
New rights must be a subset of the parent. Atomic handle move preflights target
capacity and source authority before mutation, preserves lineage, and removes
the source slot. Closing a handle does not revoke descendants; retained nodes
preserve their lineage. REVOKE invalidates its grant and all descendants while
siblings remain usable. Slot reuse changes generations; exhausted generations
fail closed. Descriptor destruction requires CONTROL and rejects every remaining
capability to the dead descriptor.

## Bootstrap boundary

Space creation and root mint are trusted bootstrap primitives, not userspace
calls. Runtime creation must receive explicit creator/allocation authority.
Object kinds identify descriptors, not implemented Memory Objects, processes or
Jobs. This slice does not destroy physical mappings or running processes. Real
teardown requires quiescence, active-operation exclusion and resource release.
No node/object reclamation or public ABI is promised by these fixed capacities.

The BAC manifest, sealed roots, incarnation state/digests and reconstitution are
separate required work. Retained lineage is a prerequisite, not a BAC proof.
IPC must make transfer atomic with message acceptance; handle move alone does
not satisfy that transaction or receiver-death semantics.

## Verification

Host tests exercise owner/class/right denial, attenuation, delegation rights,
revocation through closed intermediates, sibling survival, transfer uniqueness,
full destination atomicity, stale generation rejection, dead descriptors and
capacity/exhaustion. The kernel executes a bounded table fixture in QEMU after
thread/preemption proofs. Its marker says scope=tables; userspace enforcement
and hardware resource lifetime remain pending until integrated proofs pass.
