# ADR-0119 — Bounded staged File verification

Status: Accepted Internal Level B refinement; native qualification pending.
Date: 2026-11-16
Related: ADR-0109/0110/0118; INV-IPC-002/004/005, INV-LIFE-002; M8-03/08/11/12.

## Measured problem

`WORKSPACE_1M_COMMIT_CUT_FAILURE_02.json` retains an actual coherent Root10,
legacy-capable Workspace and finite-transfer Editor VM. The full 1 MiB load
completed and all 256 Save chunks were acknowledged. Commit request 514 then
exceeded its original 8192-tick cut (deadline 87288); finite quiescence failed
at tick 88312 with the original owners retained. Independent read-only cold
inspection found the exact original committed revision 2 and a fully written
pending stage. Its declared digest is not independent stage verification.
There was no Saved result, publication, repair, retry or recovery acceptance.

The finite whole-transfer allowance from ADR-0118 solves the earlier Load
failure but cannot make one expensive accepted Commit fit its request cut.
Raising that accepted cut, renewing it during polling or discarding stage
verification would weaken the existing contract. Keep those limits intact.

## Decision and exact scope

Add optional opcode 7, `Verify`, to the generated Internal File@2 contract.
The actual authenticated route still fixes the object, caller, rights and
lease. Verify requires the same live ReadWrite binding and fully written stage,
transfer token, expected revision, complete length and complete digest as
Commit. It supplies the exact already verified prefix, aligned to 4096 bytes.
Each new request verifies at most one staged chunk under its own captured cut.
It has a distinct request/operation nonce; it never renews an accepted request.

The service retains a small private verifier bound to the exact route
generation, token and immutable stage. A successful response describes only
the next verified prefix at the old committed revision. It neither publishes
nor allocates a durable operation, returns file authority, nor claims Saved.
Ordered prefix checks reject skipped/old ranges. Matching RAM replay/query
preserves the exact observed verification response, never substitutes the
durable written prefix. Foreign/revoked/READ-only callers cannot advance it.

Commit consumes only a complete matching verifier and atomically publishes
through the existing durable operation/receipt path. Incomplete or substituted
proof is refused. Old clients that omit Verify retain the previous one-request
Commit behavior; there is no persisted format or File@1 change. An actual
successful Abort or independently quiescent retirement clears the verifier
with the stage. Uncertain I/O retains the exact accepted request, verifier,
stage, frozen proposal and window. Service replacement cannot restore a live
verifier from identifiers or the declared stage digest; it needs actual
reconciliation/recovery and fresh verification.

The native Editor leaves the immutable proposal in CommitReady while issuing
these distinct requests. One captured whole Save horizon includes all chunk
writes, staged verification, Commit and independent committed readback. Saved
still follows exact revision/digest/readback. No Kernel, Block, request, Job or
stack limit changes. The host observer must distinguish preserved baseline
integrity from successful publication of the exact edited revision.

## Required qualification

Exercise empty/partial/full chunks; bounded per-step reads and zero writes
before Commit; skipped offsets, wrong stage metadata, different route,
revocation and READ-only refusal; exact replay/query; retained uncertainty;
and final exact cold committed bytes. Run generated-contract checks, existing
File/namespace/client regressions, native strict lint and linked ELF/stack
preflight. Then execute actual 1 MiB load/edit/Save/readback and independent
cold verification with unchanged per-request cuts. Interrupted verification,
publication, service/device death, stale writers, space and cancellation
remain separate M8 requirements. Component tests alone close no gate.
