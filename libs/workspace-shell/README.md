# Bounded workspace interaction core

`ev-workspace-shell` is an Internal `no_std`, allocation-free **host/model core**
for M8, with software composition of independently borrowed app surfaces.
It does not execute a native desktop, IPC, file mutations or actual kernel grants.
Actual adapter, target resource and VM qualification are
still required. See [ADR-0106](../../architecture/adr/ADR-0106-workspace-interaction-and-protected-consent.md)
and the [interaction contract](../../architecture/designs/WORKSPACE_INTERACTION.md).

Four fixed admission roles are Files, EditorOne, EditorTwo and Inspector. Every
live role has a full generation, independent process/incarnation and independent
surface identity. Bounds, z-order, focus, modal routing and Shell replacement
share one model. Views differ in disclosure; changing Layer never authorizes a
process. Per-window semantic trees commit with the matching displayed revision,
and expose labels, roles, values/ranges, actions and bounds without copying a
whole document. One explicitly granted semantic provider has an independent
assistive focus and a bounded, single pending action ticket.

Controller setup returns a non-cloneable `TrustedAdapter` issuer. Keep it out of
ordinary Shell/App/provider handlers. Only that issuer can create private,
consumed attention/presentation witnesses. Confirmation checks current instance,
attention, nonce, target, rights, completed frame and fresh input barrier. A
provider can inspect protected semantics, but ordinary `Activate` cannot approve
a picker or owner override. The separate assistive-confirmation path still
requires the actual trusted adapter, fresh protected input and a current provider.

The issuer makes reducer entry paths distinct. It does not authenticate real
hardware or a human: integration must bind actual endpoints, verified target
metadata, protected scanout completion, Input release history and current fresh
input. An `Effect` is an admitted model request, not evidence a grant was applied.

`composition` uses `ev-graphics::Pixels/Canvas` to paint opaque window surfaces,
Shell chrome and separately issued protected Root frames. Preflight checks exact
owner/surface generation, stride/extent/dimensions and matching model/tree/frame
revisions. Prepared scenes are single-use and fenced by model/provider changes.
Hidden windows have no accepted borrow. Old resize frames refuse; row padding
and source high bytes cannot escape content clips. Integer scaling, contrast and
focus styling use the same Desktop preferences and logical window geometry.
The reserved Root rectangle is excluded from every ordinary app/chrome pass,
even when no protected overlay is supplied.

The actual adapter must retain immutable source credits and sole output ownership,
then await real Display completion before treating a composed scene as visible or
routing input against its geometry. A `Composed` receipt confirms successful
pixel writes through the supplied sink; it is not a hardware Present acknowledgement.

The crate temporarily has its own `[workspace]` for narrow independent checks.
Root workspace registration, generated UI wire bindings, renderer/IPC adapters,
storage coupling, real process/device recovery and M8 acceptance remain separate.
