# ADR-0046 — Owned surfaces and userspace Display

Status: Accepted mechanism; first bounded physical execution PASS.
Date: 2026-10-27. Owner mandate Level B;
no foundational change. M0/m0 and all historical evidence remain unchanged.

The existing one-page memory binding and two-MiB executable window cannot
represent an application surface plus a real framebuffer safely. Treating the
firmware framebuffer virtual address as physical RAM would violate mapping,
cache-type and allocator ownership. Granting raw scanout to applications would
violate the permanent Surface boundary.

The first implementation therefore extends owned Memory Objects with bounded
multi-page RAM extents. One 63-page parent-charged allocation backs a 320x200
XRGB8888 application surface with 64-byte versioned header and 1984 zero tail
bytes. App maps RW; Display maps READ. Each mapping is a move-only exact claim;
revocation does not authorize backing reuse before actual mapping/CPU quiescence.
Legacy single-page APIs remain available and unchanged.

Only the separately measured Display process receives a distinct Display object
and its device-only aperture. The actual retained four-level page tables are
walked for each source framebuffer page, including huge-leaf PAT normalization.
Original cache/PAT/MTRR conditions must remain stable. Usable-RAM overlap,
unsupported formats, excess extents, reserved bits and guard conflicts reject
before attachment. VRAM is never made into an allocator PhysicalFrame or freed
as RAM. The guarded 4–8MiB user window needs exactly two new owned RAM PT frames.

Those two tables are part of an additive versioned measured ServiceImage layout
reservation. Ordinary Registry admission charges their actual private RAM cost
before allocation and compares truthful loaded layout/frame information. The
legacy v1 descriptor digest, bounds and activation semantics stay identical.
The actual Display-table owner supports explicit inactive attach, actual stopped
process detach, scrub and return of only those two RAM frames.

The first Present path has one credit and one actual App thread. Rendering ends
before protected RPC acceptance, the caller blocks while Display copies, and
only the actual checked reply returns write credit. No admitted timeout,
cancellation or App thread spawning is in this first profile. Any failure
retains every physical owner and stops/quiesces both users before frame reuse.
This does not claim a general asynchronous release-fence protocol.

The first two-actor implementation links App 17 private frames and Display 15
private plus 2 reserved frames; adding 63 surface pages gives 97 RAM frames. This
fits existing allocator/authority capacities, so no pool enlargement is required
for that first proof. A later full Root/Shell/Input/File/Block/App graph needs its
own exact resource/stack census before any bounded pool change.

The host test frontend uses a private QMP socket only for actual device key
injection and real scanout capture. It records finite, identified command/reply
exchanges and exact framebuffer bytes. It does not supply synthetic guest input
results or replace the framebuffer with the app's RAM buffer.

Planned validation: portable extent ownership/admission and wire tests; real CPL3
App/Display presentation; independent scanout verification; actual App-aperture
and Display-write-to-RO-surface page faults; guard/authority rejection; complete
mapping/table/private-frame retirement. Then ordinary Root-created graph,
trusted input/focus, genuine picker grant, app crash and relaunch complete M4.
The [first three-world physical execution](../../docs/release/0.1-preview.md#validation-and-provenance)
passes protected presentation, exact full scanout and both contained authority
faults with 97 peak RAM frames and complete retirement. This is component
acceptance; the complete graphical gate remains required.

The safe core declares narrowly annotated unsafe implementation contracts for
`RamAccess` and `DisplayBacking`, matching the existing `LoadedExecutable`
pattern. Core performs no unsafe operation. The actual binary HAL must address
only exact owned RAM or the validated non-RAM source, perform truthful volatile
initialization/readback and retain no Rust alias. Display copies pixels in
userspace and issues SFENCE before replying, so write-combining stores are
published before credit returns. These are explicit ownership/order boundaries,
not readiness flags or alternative authorization paths.

MTRRs/source tables must remain unchanged under the exclusive BSP/AP-parked
hardware precondition. The current HAL reads actual CR3/CR4/CR0/EFER/PAT and
walks source pages; it does not claim a separately captured MTRR-register dump.
SMP, dynamic cache-type changes and arbitrary hardware are outside this slice.

The full graphical graph must preserve E-017.35/.70: Shell has no display
hardware and its failure leaves the compositor alive. Root, Shell, Display/
compositor, Input, File, Block and App therefore require separate failure
boundaries in the next graph; the two-actor slice does not accept a six-process
co-location shortcut. Startup-capacity and running-app grant delivery need
explicit bounded integration before that full gate.
