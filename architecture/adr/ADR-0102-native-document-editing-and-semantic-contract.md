# ADR-0102 — Native document editing and semantic contract

Status: Accepted Level B; bounded M7 VM runtime qualification PASS. See the
M7 acceptance (local engineering archive) for the
exact source/build scope. New 0.4 formats and capacity still require review.
Date: 2026-11-15
Related: M7-01–10, ADR-0043, ADR-0044, ADR-0046, INV-AUTH-002, INV-AUTH-003,
INV-IPC-002, INV-IPC-005, INV-LIFE-002, INV-USER-004

## Context

The accepted reference can display selected READ-only File contents and edit a
separate private demonstration note. It does not yet offer a coherent workflow
that edits the selected File itself. The File service already has distinct
READ/replace routes and atomic File-v1 envelopes, but picker approval and its
durable policy deliberately authorize READ only. Reusing that approval to mint
a write endpoint would change its authority meaning.

## Decision

1. Add an Internal IDL-defined native document contract with bounded text,
   named focus/control identities, selection, permissions and semantic save/error
   states. Generate checked bindings before the renderer/client use them.
2. Reuse the existing File-v1 service and 224-byte per-object payload bound.
   Reference selection presents Notes.txt and Private.txt. Keep immutable app
   packages, selected document data and legacy private-note data distinct.
   No on-disk format or silent data migration is introduced.
3. Extend the canonical picker implementation with explicit incarnation-only
   edit selection. Bind requested access into approval and displayed intent.
   A separate typed edit handoff cannot be obtained from READ approval. Preserve
   the existing READ path and durable READ policy without widening their rights.
4. A selected write endpoint fixes the exact File object. Actual kernel grant
   delivery still targets the current app incarnation through the existing
   protected inbox; neither IDL metadata nor a name/identity grants authority.
5. Serialize each File frame. Save uses the next exact per-object counter,
   retains the proposed payload, validates completion and reads back the same
   committed counter/content before publishing Saved. Accepted-operation error
   or timeout is uncertain execution, requiring explicit recovery/quiescence;
   no automatic fresh-counter retry or frame reuse is permitted.
6. Expose supported keyboard/pointer controls and semantic information using
   the same contract. Preserve unsupported document bytes and report unsupported
   input/rendering cases honestly. Do not infer a screen-reader/IME provider or
   complete system-wide three-layer UX from this bounded implementation.

## Alternatives

Saving an imported File into the private note would edit a different object and
would need explicit Save Copy semantics; it does not meet selected-document Save.
Granting write access from the existing READ callback would silently amplify
approval. Adding a second general storage/capability mechanism would duplicate
existing concerns without a demonstrated need. A new filesystem or arbitrary
directory UI is outside the selected document-workflow goal.

## Compatibility and failure

Existing File-v1/Store-v2 bytes and old READ bindings remain valid. The previous
private-note schema is untouched. Unknown/corrupt content is never reset to make
the editor work. Dirty state survives cancelled navigation; explicit discard is
separate from Save. App death retires edit authority, and reopening needs a new
selection rather than serializing a runtime handle. A failed app update must
recover the same independently stored document through the existing lifecycle.

## Verification and review trigger

Use [M7 acceptance gates](../M7_PLAN.md), source-pinned host/target and actual VM
evidence. Observe exact object/counter/readback, actual capability delivery,
failure/recovery and unchanged sibling/private data. Measure all affected linked
resource profiles before adoption; no stack/image budget increase is assumed.
Review when adding durable edit grants, new File formats/capacity, more writers,
text/input methods, an accessibility provider, or a new public contract maturity.

## Current reference integration refinements

The document profile adds a separately declared optional `SelectedFileEdit`
capability request and generated `ev.app.document@1` controls. Minor1 of focused
input adds Left/Right while preserving the five legacy key frames. The reference
kernel adapter joins actual current requester/control, explicit trusted picker
access, fresh presentation/barrier and exact selected File route; these checks
extend the existing reference adapter and grant no new general primitive.

The Shell/App document profile uses size optimization and one codegen unit to
fit unchanged frame admission. Native3 Root uses opt-level2 with one codegen
unit after measured image admission failures. V4 document Root retains the
existing opt-level3/16-unit profile: applying Native3's settings overlaps its
fixed stack, while size optimization exceeds its stack census. The measured
ordinary V4 profile fits its unchanged image and stack bounds. ThinLTO is
excluded because the pinned prebuilt core has
a different code model.
The document Native3 Root reuses the existing single-claim private resident Root
initializer already used by V4, with exhaustive field initialization and scoped
startup borrows. No backend owner is duplicated and no static mutable reference
is fabricated. This changes private storage placement, so actual linked frame,
stack, retirement and execution proofs remain required before acceptance.
The existing phase-local kernel bootstrap helper is also out of line for this
new long-running profile under ADR-0101's same owner/refusal rules.

Downloaded document applications retain the existing genuine startup-health
sequence: read the separate saved private note, present that coherent Saved
frame, then report Critical. The document view becomes interactive after the
existing Root health/reveal barrier. Merely rendering a closed document never
substitutes for that health sequence. Signed application versions0.3.1/0.3.2
use a separately checked eight-contract metadata profile; declarations still
grant no endpoint. Exact old packages and their independently stored data keep
their original version and bytes.

The retained manual session disables document-text serial observation by
default. Explicit conformance fixtures enable it separately. Actual Save
interruption evidence must match a paused protected Saving scanout and an owned
child's termination; it cannot imply that a File request was accepted or that
all physical power-loss positions were tested. Read-only cold inspection must
refuse any write/repair attempt.

[ADR-0103](ADR-0103-v4-bootstrap-source-retirement-and-grant-headroom.md)
records the V4 bootstrap source lifetime correction for recovered B retaining
both downloaded images. Its new qualification remains separate from the failed
source09 run and preserves all selected-grant checks.
