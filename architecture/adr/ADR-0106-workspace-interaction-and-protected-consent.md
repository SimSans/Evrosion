# ADR-0106 — Bounded workspace interaction and protected consent

Status: Accepted Level B model direction; actual adapter/runtime qualification pending.
Date: 2026-11-15
Related: M8-01/04/05/06/07/08/10; ADR-0046/0047/0102;
INV-AUTH-001/002/003/005, INV-LIFE-002, INV-USER-002/003/004

## Context

M7's App/Shell pair, fixed App rectangle and flat document snapshot establish
bounded isolation and selected-document editing. They do not establish concurrent
window ownership, responsibility-layer interfaces, a semantic provider or trusted
attention independent of normal Shell input. E-017.25–26/.69–82/.89–97 and F-003
already define the direction. E-009.15–19 forbid treating an administrative label,
signature, name or ordinary semantic action as owner authorization.

## Decision

1. Introduce `libs/workspace-shell` as an allocation-free Internal interaction
   core. Its initial four admission roles are Files, two independently owned
   Editor instances and Inspector. Full window generations, actual owner
   process/incarnation and full surface identities remain separate. The core
   governs z-order, clamped geometry, activation, focus, app-modal ownership,
   stale queued delivery and Shell replacement without inventing memory access.
2. Simple, Advanced and AbsoluteAccess are progressively deeper views of the
   same live window state. Layer selection changes disclosure only. It never
   installs, widens or exempts a process capability. Unsupported hardware/boot/
   administrative operations remain explicit future integration work.
3. Publish a bounded semantic tree with a matching displayed view revision.
   Nodes carry stable local identity under a full WindowId, parent, role, label,
   state, value/range, supported actions and logical bounds. Sixteen nodes per
   window and 64-byte labels are initial model envelopes, not permanent platform
   limits or a public wire ABI. Large text is range metadata, never a per-key
   whole-document copy. Tree construction rejects forward/cyclic parents,
   duplicates, malformed geometry and overflowing ranges before publication.
4. Bind one explicitly admitted semantic provider to its actual incarnation and
   non-repeating lease generation. READ and ACTION are separate. Assistive focus
   differs from keyboard focus. A single pending semantic action ticket must be
   revalidated and consumed before actual delivery; replacement, revocation,
   view/modal change and stale owner identities fence queued actions.
5. Controller setup returns a held, non-cloneable `TrustedAdapter` issuer with a
   unique in-process Desktop binding. Only that issuer constructs private,
   consumed attention and presentation witnesses. A protected challenge includes
   kind, actual requester, exact target descriptor, rights and non-repeating
   nonce. Confirmation additionally matches current attention, completed protected
   frame, Input barrier and freshly re-resolved target/rights. The actual adapter
   must prove released activation state and fresh protected input; a number or
   queued event alone cannot establish consent.
6. Ordinary semantic Activate/Focus cannot approve protected picker/owner nodes.
   A semantic provider can inspect the current protected challenge. Deliberate
   assistive confirmation has a distinct actual-adapter path requiring a fresh
   protected event and a current READ+ACTION lease. A provider descriptor alone
   cannot create attention/presentation witnesses or actual grants.
7. Add bounded software composition behind `ev-graphics::Pixels`, consuming
   independent immutable source borrows supplied by the actual adapter. Preflight
   exact dimensions/stride/extent, owner, full surface/window generations and
   matching model/view/tree/frame revisions. Paint z-order, clipped Shell-owned
   decorations and separately owned modal surfaces. Hidden windows have no
   accepted source borrow. Stale resized sources refuse rather than stretching
   older pixels over newer semantic geometry. The Root-reserved rectangle is
   excluded from all ordinary App/chrome passes; a private protected-frame token
   is issued only through the held trusted adapter. Integer scale, contrast and
   focus preferences are actual Desktop state and fence older prepared scenes.

## Actual adapter obligations

Model `Owner`, `Surface`, target and lease values describe objects. They do not
authenticate a sender, prove a mapping retired, authenticate a human or create
kernel authority. Controller methods are reached only after actual endpoint and
ownership checks. Never expose the `TrustedAdapter` issuer to a wire decoder,
normal Shell/App/provider or an untrusted plugin.

The returned `Effect` is a scoped model request. Root must separately revalidate
the actual current recipient, target route/metadata, rights, capacity and delivery
transaction. Only actual installed capability effects establish an M8 grant
proof. Object namespace revisions returned by the storage adapter are compared
at presentation and confirmation; neither an object number nor a name is access.

An immutable Rust source slice is valid only while the actual adapter retains
the real mapped extent, writer quiescence/blocked Present credit and no unmap or
device reuse. The composition crate contains no arbitrary-address constructor
and does not replace the existing volatile mapping boundary. Safe pixel writes
produce a `Composed` receipt only on full sink success; a sink error can leave
partial pixels and advances no composition/frame clock. Neither receipt nor
equal revision integers prove actual scanout completion. Root must wait for the
real Display acknowledgement before publishing matching input/semantic geometry.
Shell decoration semantics use the same composition geometry/revision helper.

Trusted attention must bypass ordinary Shell routing and remain reachable with
Shell blocked/dead. Protected presentation must not be spoofable/coverable by an
ordinary window. Real Input/Display failure, replacement and protected prompt
recovery need actual adapter and VM tests. Host witness separation cannot prove
them. The interaction model contains no App content renderer, serial approval
shortcut, synthetic human acceptance or speech accessibility claim. Pixel
composition is separately qualified from native process/scanout execution.

## Compatibility and qualification

This adds an Internal model and changes no existing File-v1, Store-v2, package,
kernel ABI or M7 semantic bytes. It does not widen READ grants, copy app code into
Root, introduce ambient root or implement a whole-system Absolute Access path.
The separate generated storage/namespace contracts remain owned by their actual
service adapters. Future UI wire layouts require their own IDL/generation and
compatibility review; the Rust layout is not a cross-process ABI.

Narrow host tests cover four owners, focus theft, modal/subtree confinement,
generation reuse, coherent view publication, provider replacement/revocation,
queued action replay, presentation/input cuts, scope changes and distinct
adapter bindings. Check the crate for the bare target and measure its actual
linked use before integration. No host test closes M8 runtime/resource gates.
Concrete adapter/API details are in
[WORKSPACE_INTERACTION](../designs/WORKSPACE_INTERACTION.md).
