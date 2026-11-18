# ADR-0094 — Measured V4 cohort-controller capacity

Status: Accepted Level B refinement in private components; Main integration and fresh joined guest qualification remain pending.

## Problem and measurements

The [208-page acquisition profile](ADR-0093-measured-v4-acquisition-capacity.md)
fits the actual signed-download/cold-B checkpoint. Adding retained publisher
proofs, genuine System health, fault evidence and owner controls exceeds that
image ceiling. Early cohort components also exceed the unchanged 32 KiB Root
stack. Compilation or changing a constant cannot resolve both admission gates.

Retain all refused components. Separate System health acknowledgement from
the subsequent acquisition Known Good continuation, finish fault readback in
the existing owning continuation, and use the established one-claim resident
storage pattern for Root's retained fields. Canonical verification/publication
remains shared; no alternate Snapshot, accepted-I/O retry or renewed deadline
is introduced. Broad inlining and the measured size-optimization alternatives
are not adopted when their stack/code tradeoff fails either bound.

The resulting health component measures 219 image pages, 225 initial private
frames and 31,272/32,768 resolved stack bytes, with zero unresolved indirect
calls. The initial owner-control component separately measures 222 image pages,
228 initial private frames and 31,448/32,768 stack bytes. These are different
private component sources. They do not prove the final joined source fits.

## Decision

Set only the explicit V4 constructor's ceiling to 224 image pages, 228 image
owner slots and 230 initial private frames. Retain ordinary 64/68 and Native3
96/100/102 image/owner/initial limits. Keep Root's 32 KiB guarded stack, Kernel's
256 KiB stack, Root 512-frame limit, Boot 1,024-frame limit, 64-handle/object
limits, child quotas, package bounds, W^X, guards and retirement requirements.
The new image ceiling is an admission bound, not a simultaneous maximum-package
or additional-actor reservation.

Bind the new values in the V4 ABI and dynamic-admission description, loader,
owned image storage and Core checks. The private V4 description digest is
`b86c1e5c6feae4b86ec2015ea9feb589e770199df9fb01f034badbe0220a1ade`;
the private dynamic description digest is
`7e282a01b2f684b2b538b524ac7aaf53fb7ee648457bac6033c9419dadcf399c`.
Stable App/data contracts remain independent. Exact constructor and component
measurements still determine admission; an unknown or oversized image refuses.

The Root resident placement follows [ADR-0092](ADR-0092-downloaded-cohort-health-and-retained-authorization.md):
charged BSS, one aligned claim, exhaustive initialization and actual scoped
immutable bootstrap borrows. It does not fabricate static ownership or replace
explicit successful actor retirement with Rust destructors.

## Validation and limits

Core tests admit the exact 224-page V4 boundary, refuse 225 before loading,
retain older-profile denials, and check complete 228-slot mapping/reclamation
and ancestor-budget atomic refusal. The declared full-graph private subtotal
increases from 534 to 550, the conservative Root-plus-dynamic subtotal from 344
to 360, and its Boot subtotal from 664 to 680. These are model accounting
totals, not the final guest's measured peak. Correct stale expected totals
without weakening the guards.

The frozen health qualification record (local engineering archive)
records Root 227, Core 454, SDK 97 and Store 43 passing checks and independent
resident-source review. An earlier exact selected Kernel measures
253,968/262,144 stack bytes; later Recovery/test fixes mean it cannot qualify
the current source. Earlier 208-page source03 B guests remain immutable evidence
for their own source and profile.

Before acceptance, join the reviewed health, Host and owner-control changes;
recompute the source identity, actual admitted Root, complete selected Kernel
and full actor/package/frame census for each declared boot mode. Run real
downloaded B health, C fault and offline protected B recovery on the same owned
disk, plus actual owner-control and final negative/regression gates. Preserve
all original refusals and source/artifact closures. Neither this capacity change
nor passing component tests establishes a new guest or whole-0.2 PASS.
