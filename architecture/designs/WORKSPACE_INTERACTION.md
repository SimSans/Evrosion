# M8 workspace interaction model and adapter contract

Status: Internal model and bounded software composition implemented; native
renderer/IPC/authority adapters pending.

## State and identity

`Desktop` admits exactly four reference roles: Files, EditorOne, EditorTwo and
Inspector. A role may be absent, but cannot be double-admitted. Each admission
gets `WindowId { slot:u8, generation:u64 }`; generations never reset/wrap. Its
`Owner { process:u64, incarnation:u64 }` and full `Surface { object,generation }`
must differ from other live window owners/surfaces. Full identity comparisons,
not slots alone, authorize a reducer transition. These are local model types,
not new kernel objects or wire authorities.

The actual controller owns install/retire/provider/recovery methods. Ordinary
Shell methods compare the current Shell owner; app publication/modal methods
compare the current window owner. Controller retirement requires the actual
stopped writer, detached mappings and settled IPC owner outside this model.
Replacing a Shell invalidates its pending confirmation/actions but preserves
surviving app windows, their surfaces, z-order, view revisions and semantic trees.
Old Shell messages cannot route input. App retirement drops its tree/focus,
invalidates protected consent and leaves other owners intact.

Bounds use signed logical coordinates and checked nonzero sizes. Move/resize
clamps within the declared display rectangle and invalidates the old semantic
geometry until a fresh matching view publication. Hit testing chooses the top
window. An app-modal Dialog owns a distinct surface and semantic subtree; pointer
events outside that modal, and semantic actions outside its subtree, refuse.
Keyboard routing selects its modal surface. Other applications remain distinct.
The actual compositor continues to enforce real surface ownership and Present
read/write lifetimes; the model grants neither RAM nor scanout access.

`InputTarget` retains the full window/owner/surface/modal tuple. The actual adapter
must call `validate_delivery` immediately before actual delivery, so a queued
decision cannot cross focus, modal, owner replacement or trusted-attention cuts.
This is not a replacement for authenticating the real Input endpoint/history.

## Coherent semantic publication and consumer

A `Tree` has at most16 nodes; each node carries a nonzero local ID, preceding
parent, role, UTF-8 label of at most64 bytes, enabled state, actions, bounds and
value. The root is a Window; parent-before-child construction forbids cycles.
`Value::TextRange` describes document revision/offset/length/total with checked
arithmetic. Text bytes remain in their separately authorized bounded-range
transport. The model does not implement glyphs, input methods or speech.

`publish_view(actual_sender, WindowId, displayed_revision, Tree)` requires the
next exact view revision and identical semantic/displayed revisions. The actual
adapter calls it only for a completed matching Present/semantic commit; passing
equal integers is not proof that pixels reached Display. Invalid publication
leaves the preceding entire tree intact. A semantic read exposes the tree,
owner, desktop/view revisions, modal ownership and both focus classes together.

The actual controller admits one provider after a real scoped grant. Its lease
binds actual owner/incarnation plus a never-reused generation. READ permits
semantic inspection/assistive focus; READ+ACTION permits supported ordinary
actions. This reference grant covers the admitted workspace trees deliberately;
it does not grant file bytes, clipboard, screen capture or protected approval.

`semantic_action` checks current provider, tree revision, node, modal, enabled
state and supported action, then reserves one action ticket. It has no storage
effect. `dispatch_semantic` rechecks current sender/lease/tree/owner and consumes
that exact ticket. Replay and a queued ticket from a revoked/replaced provider
refuse. Focus actions update keyboard routing only at dispatch; assistive focus
alone never changes keyboard focus. Republication/geometry/modal changes fence
old queued tickets. Actual endpoint delivery remains a separately checked step.

## Responsibility and protected confirmation

`View` exposes the same admitted windows, ordering, focus and current model
revision at every layer. Simple hides technical disclosure; Advanced adds
permission/diagnostic presentation; AbsoluteAccess exposes deeper state and
owner-control affordances. These flags never install authority. Actual resource,
file-grant and process diagnostics must come from the real controller/services,
not invented model counters or display labels.

Controller initialization yields a distinct `TrustedAdapter` issuer. It has no
Clone/Copy/serialization or public standalone constructor. Each Desktop binding
is unique within the process and rejects another model's issuer/witnesses.
Actual Root keeps this issuer exclusively in the trusted input/presentation
adapter, separate from ordinary Shell messages and semantic provider dispatch.

Protected transitions are:

1. `attest_attention`: actual independently routed attention and fresh event
   serial produce a private consumed attention witness. No normal Shell call is
   needed. Ordinary input/actions are blocked while attention is active.
2. `challenge`: the issuer consumes that witness after resolving an actual live
   requester and exact action target/rights. The target is a full Window/Owner or
   dataset+object slot/generation/metadata revision. Retain the real target route
   outside the model. The challenge nonce is not a capability.
3. `attest_presented`: after the exact protected frame completes, obtain a real
   Input barrier and released activation history. Re-resolve the exact scope and
   record the frame/input cut. The issuer creates a private presentation witness.
4. `attest_confirmation`: consume that witness with a post-barrier fresh actual
   event and freshly re-resolved exact scope. Identity, rights/revision changes,
   stale frames, provider replacement, target retirement and old bindings refuse.
   The result is an `Effect` request, not an executed grant. Actual Root applies
   the transaction only after final route/recipient/capacity validation.

The current protected challenge has a semantic inspection view. Ordinary
semantic Activate always refuses protected nodes; it cannot synthesize steps1–4.
An authorized assistive confirmation still enters step4 through the actual held
issuer with fresh protected input and the current provider READ+ACTION lease.
The adapter must authenticate the real provider event and deliberate owner
confirmation rather than converting an arbitrary semantic activation into an
Input witness. Revocation/replacement invalidates pending approval.

The model assumes that the adapter issues truthful attestations. It cannot prove
real secure attention, held-key release, a hardware scanout, owner presence,
malicious-Shell isolation, syscall authority or physical device quiescence. Those
remain explicit M8-04/06/07/08/10 actual-process/VM gates. Failed confirmations
consume their Rust witness and require explicit cancellation/fresh attention;
there is no implicit retry that widens rights or invents another authorization.

## Integration boundaries

### Pixel composition and publication

`composition` depends on `ev-graphics::Pixels/Canvas` and consumes a separate
immutable `AppFrame` slice for each visible window/modal surface. The actual
adapter supplies and retains the real owner, generation, mapping extent,
read credit and writer quiescence. No raw-address constructor or untrusted
cross-owner memory lookup exists in this helper. XRGB high bytes have no alpha
authority; exact declared row padding is validated and never sampled as content.

`Compositor::prepare` checks every source before writes: full owner/window/surface
identity, exact logical dimensions, stride and initialized extent; current model
revision; matching committed semantic/displayed view revision; nondecreasing
frame serials and strictly new serials when the view changes. Each visible
window and admitted modal needs its distinct frame. Hidden sources are rejected,
not borrowed or sampled. Resized old extents refuse rather than being scaled
or clipped into a newly advertised semantic layout.

Prepared scenes retain only geometry, revisions and those independent borrows,
not copies of trees/documents. A scene commits at one expected composition
sequence and rechecks Desktop/model/provider generation, protected scope and
preferences before the first pixel write. Replacement, publication, resize,
visibility or preference changes fence the older scene. A successful helper
commit returns exact window/owner/view/frame revisions; failed sinks return no
commit and advance no frame clocks, although output pixels may be partial.

Window.bounds denotes App content in logical desktop coordinates. Shell-owned
chrome is painted around it and clipped to the display; modal chrome additionally
clips to the parent window. `Compositor::geometry` derives the same content/title/
decoration geometry and model/view revisions for Shell semantic controls.
App pixels stay inside their content rectangle. Scale1–4 maps logical pixels to
integer physical blocks; inverse point mapping uses the same preferences and
returns no ordinary target in Root-reserved pixels. High contrast and focus
styling affect Shell chrome, with an explicit non-color active marker; App
content contrast/font preferences must be implemented by independent clients.

The reserved Root rectangle is always excluded from ordinary App and chrome
painting, before sampling ordinary source pixels. A protected Root source has
no public token constructor: the held `TrustedAdapter::borrow_protected` binds
its separately owned surface to this Desktop, current attention/challenge,
model revision and exact reserved extent. Another issuer, an App owner, stale
protected scope or reuse of a frame across a changed scope refuses. Root pixels
are applied through the separate protected pass; absence of that frame leaves
neutral compositor-owned pixels, not guessed confirmation UI.

These pixel helpers do not supply actual process isolation, mapping retirement,
hardware Present, trusted Input or human presence. In particular, the actual
adapter must wait for real Display completion and match the retained composed
scene/revisions before publishing its interaction geometry or routing input.
Old scanout pixels after a failed/stale composition cannot justify new geometry.
All surface credits remain retained until actual completion/quiescence. Host
tests check pixel values, guard extents, clipping and refusal, not VM screenshots
or native acceptance.

### Storage and native integration

Namespace/storage owns ObjectId, DatasetId, durable revisions, chunk loans and
receipts. The IDL definitions own generated Internal file/workspace codecs. This
crate intentionally contains no parallel wire encoding or private Root layout.
The future UI schema should bind every node/action to full window generation,
actual owner, coherent view revision and current provider lease, with bounded
range reads. Protected confirmation is a separate trusted protocol, never an
ordinary action flag sent by an application.

Root still needs actual source-bound authority/mapping adapters, dynamic process
admission, native renderers/composition adapter, real Input routing, independent
trusted presentation, generated UI transport, storage-backed Files/Editors,
accessible preferences/recovery and resource/stack/overlap qualification. The
four-window model and its host tests do not close those runtime gates.
