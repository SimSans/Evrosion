# M8 native Display actor

`ev-workspace-display` is a separate executable for the selected V5 Display
profile. It preserves the legacy `services/desktop` compositor and its fixed
V1 surface protocol. Native execution is behind `native-actor`; the library is
a `no_std`, unsafe-free policy/composition core.

The actor parses the exact 528-byte/ten grant Display startup record and checks
actual handle rights. Its six READ-only source mappings are independently fixed
by the selected Kernel/Root admission: Files, Editor1, Editor2, Inspector, Shell
and protected Root. The hardware Display capability is role 8, shared Present
receiver 7, Events 9 and the Root-only control receiver 10. Only Root receives SEND
authority to receiver 10. Source-role identities in bytes do not grant access.

Before reading any ordinary header or pixels, Display queries the negotiated
ServingOrigin 57/58 ABI on the actual received endpoint and serving nonce, checks
the live finite call and resolves the actual process/thread/incarnation against
a Root-installed registration. Present's scalar body is the complete 64-bit frame
number. Display then snapshots the strict V5 header, validates exact owner,
source, mapping epoch, dimensions, extent, model and view revision, and samples
only this caller's source. Each row queries actual ServingOrigin field7 on the
same retained RECEIVE handle and full serving nonce, checks its canonical live
result and original deadline. Kernel authenticates the exact retained call on
each query; fields0..6 cannot change during it. A final unchanged header, full
eight-field origin recapture and MMIO store completion precede the exact 64-bit
frame reply. The finite 1024-tick presentation deadline is not renewed.
Refusal returns `u64::MAX`; an RPC transport failure is an uncertain loan and
requires producer quarantine until actual completion or process teardown.

No shared Rust borrow over a runnable producer is created. The native boundary
uses bounded volatile reads of the currently blocked caller only. This relies on
the admitted single-thread producer, no DMA or other writable mapping, retained
source mappings and Root's promise not to map/write ordinary source pixels.
Cancellation can interrupt a copy, so validated copying first invalidates the
old accepted readiness. Refusal never advances its accepted frame or restores
readiness over partial scanout. These obligations still require native
integration qualification.

Root control uses the separate 256-byte `EVDSPL05` codec at protected-source
offset 256. Root serializes control bytes with protected Present ownership. The
actor snapshots control during that exact Root-only RPC. Begin/Register/Remove/
Commit/Abort provide a bounded staging transaction. A Commit requires a larger
full 64-bit model revision, unique actual owners, unique visible application
z-order, and at most one focused application. Registration binds the exact
actual owner, logical source ID, generation, mapping epoch, bounds and optional
exact semantic view. A changed geometry/model clears readiness and returns a
six-bit `NeedsRepaint` mask. Inspect reports retained mask/model/frame/view/epoch.
Inspect field6 is a monotonic presentation-state stamp. Root brackets separate
metadata queries with the same nonzero stamp; a copy, accepted frame or scene
commit changes it, so a split observation cannot authorize view routing.

Composition is incremental. Geometry Commit clears ordinary pixels to neutral
and redraws trusted window chrome without reading any application. Root must
then obtain fresh Presents from exposed producers. A lower window's copy skips
all higher trusted window extents and the Shell panel; occluded source pixels
are not read. The Root 640x80 plane is excluded from every ordinary clear, chrome
and copy. Only the separately registered actual Root producer paints it, with
pixel offset 512. Root must fence protected input/confirmation until a current
protected presentation has completed, including after model or scaling changes.
Pixels alone do not authorize confirmation or establish semantic completeness.

The logical desktop is 640x480. Applications are at most 320x180, Shell 640x18,
and Root 640x80. Integer scale 1..4 is accepted only when the admitted hardware
framebuffer fits the entire scaled desktop; otherwise control refuses it.
Contrast and focus thickness apply to compositor chrome. Display uses the
actual `DISPLAY_INFO` aperture/format/stride/extent and volatile scanout stores.
Its source windows, absent guards, private stack 480..487 and 80-page image bound
are selected M8 resource metadata, subject to linked-image admission and census.

Host tests exercise policy and deterministic pixels, including wrong-origin
rejection, overlap, protected-plane exclusion, exact revision/epoch checks,
hidden surfaces, replacement, interrupted copy, scale and guarded output. They
do not establish actual native boot, scanout, input protection, semantic client
delivery, accepted health, recovery or M8 acceptance.

Retained component preflight: `B8/display-native-02` contains the canonical
66,928-byte ELF and original debug ELF, with exact bytewise loaded identity. The
linked image uses 21 pages (13 code/data plus 8 stack); the selected loader formula
therefore proposes 29 frames including private-loader and Display table overhead.
The resolved fixed-prologue entry census is 8,816 bytes against the 32KiB guarded
stack, with no unresolved indirect calls or cycles in that census. Receipts
`ux40`, `ux42`, `ux45`, `ux49` through `ux53` retain the corresponding host tests,
strict lint, final link, strip, stack, format and legacy-preservation commands.
Actual Kernel admission and runtime high-water checks remain integration work.
