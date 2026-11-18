# M7 / Evrosion 0.3 — Native document workflow

Status: PASS for bounded local VM engineering; acceptance (local engineering archive). The owner explicitly selected this goal on 2026-11-15 after
0.2 stabilization. The desktop/folder/layer
questions were exploratory; the owner corrected that interpretation and selected
the existing bounded document-workflow proposal. This plan records that scope.
No new human usability acceptance is implied by the implementation go-ahead.

## Outcome and reference bounds

Boot the owned QEMU reference, launch the native application, explicitly select
a local text document, edit it, save with an honest durable result, close and
reopen it. Reboot, app failure and a failed application update must preserve the
same saved document. Cancellation, refusal and storage failure must be clear.

The first reference uses the existing independently stored `Notes.txt` and
`Private.txt` File objects. The unchanged File-v1 payload bounds each document
to 224 bytes. The new editor exposes the whole supported document, its current
selection/focus, capacity and durable save state. This is an explicitly bounded
developer document workflow, not an arbitrary file manager or a new filesystem.
Names identify presentation choices; live per-object capabilities authorize I/O.

The existing 0.2 private note, File envelopes, per-object counters, Store-v2,
System/data separation and protected Known Good remain compatible. The new
document view coexists with the previous private-note data; it does not migrate,
reset or reinterpret it. Unsupported text is reported without rewriting bytes.

## Direction and mechanism

Follow F-001–F-014, U-000–U-018, E-008/E-009/E-010/E-015/E-019,
[governance](GOVERNANCE.md), [invariants](INVARIANTS.md), and
[ADR-0102](adr/ADR-0102-native-document-editing-and-semantic-contract.md).

Define the text/focus/semantic-state interface in language-neutral IDL before
expanding the view. Generate checked bindings and use the same named controls
for keyboard/pointer focus, rendering and semantic information. State precisely
which text input, glyphs and accessibility providers are implemented.

Opening for editing requires displayed edit intent and fresh trusted picker
confirmation. Read and edit approvals share one bounded picker mechanism while
remaining distinct types/rights. Existing READ approval, remembered READ policy,
or a selected object name cannot authorize a write route. Edit grants last only
for the actual application incarnation and remain confined to one File object.

An app issues at most one File operation against its retained frame. Saving
preserves the exact proposed counter/payload until completion. Only matching
commit acknowledgement plus readback of that revision/content permits Saved.
Timeout/error after acceptance means uncertain execution; do not invent a new
counter, reuse the frame, or silently retry. Recover or reselect explicitly.
Dirty navigation must preserve the edit or ask for explicit discard.

The three responsibility layers, native independence, optional AI/compatibility,
accessibility and future consumer requirements remain architectural commitments.
This slice makes no claim to complete their system-wide interfaces. The VM
reference remains Internal/BSP/non-DMA/development trust. Physical qualification,
general Kernel/Root replacement, publication and official signing are separate.

## Gates and proof

| Gate | Required result | Authoritative proof |
|---|---|---|
| M7-01 | Scope, compatibility and contracts recorded | Plan/ADR/schema review, checked generation and canonical-source integrity |
| M7-02 | Bounded editor and semantic-state contract | Actual codec/editor refusal, UTF-8/boundary, focus, dirty/save and uncertain-completion tests; no storage authority in the model |
| M7-03 | Explicit exact-object edit grant | Shared picker model plus actual fresh-input VM delivery; READ cannot replace, sibling remains unchanged, cancel/stale/restarted requester cannot gain authority |
| M7-04 | Native open/edit/save/reopen | Actual ordinary application and File/Block processes, visible controls/status and independently inspected persisted bytes/counters |
| M7-05 | Compatible cold use | Same owned 0.2-compatible volume, no reset; saved document and legacy private data survive shutdown/reboot/reselection |
| M7-06 | Refusal and failure behavior | Actual cancel/denial/app crash; storage-capacity/interruption cases at their declared model/device scope, uncertain execution retained, no false Saved |
| M7-07 | Failed-update recovery | Real admitted good/bad application versions, actual failure and offline Known Good recovery with the same later document edits |
| M7-08 | Resource and response qualification | Actual optimized linked stack/image/frame gates for affected profiles; source-bound response/IPC measurements with retained failures and analyzer limits |
| M7-09 | Reproducible and usable checkpoint | Exact source/artifact pin, same-host fresh-path comparison, exercised graphical guide and appropriate regression matrix; human feedback separately recorded |
| M7-10 | Qualified integration and implementation status | Guarded adoption with preimages and source history preserved; current architecture and implementation notes with recorded qualification results |

Host models, code generation, Ready, pixels, signatures, health and acceptance
are different proofs. A gate passes only on evidence matching its scope. Retain
failed attempts, source inventories, raw output/media and data before/after.
Do not inherit snapshot14 or stabilization whole-source proofs for changed code.

Qualification preserves compilation-input preimages and original historical
proof hashes. Runtime changes are adopted only after appropriate validation.
The original bounded engineering results remain in the local engineering
archive; they do not establish physical qualification or human usability acceptance.
