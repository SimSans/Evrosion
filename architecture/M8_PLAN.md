# M8 / Evrosion 0.4 — Recoverable Native Desktop Workspace

Status: ACTIVE, selected by the owner on 2026-11-15 through the implementation
goal. Execute all 14 gates below. M7 acceptance remains preserved; no M8
runtime qualification is inferred from the selected goal.

The architecture already exists through E-026, the R-series, foundations,
universal rules and accepted amendments. The numbered implementation roadmap
is a delivery index. It is not the limit of Evrosion's design. This checkpoint
implements a coherent vertical slice under E-026.106–107.

## Product outcome

Boot the owned VM into a usable native desktop. Create a folder and a new text
document, organize them, open the document in an independently packaged editor,
edit and save a useful multi-page document, and manage several windows. Reboot
and find the same names, identities and contents. A failed App update or
affected service failure must preserve committed work and offer an honest,
usable recovery path.

The same workspace has three progressively deeper presentations: simple daily
tasks, advanced inspection/settings, and deliberate owner control. They act on
the same real files, applications, permissions and state. Selecting a layer
does not grant a process authority. Every new interaction exposes accessible
semantics alongside its pixels.

This is a substantial native desktop/workspace alpha. It is a first coherent
implementation of responsibility layers for the supported workspace operations,
not a declaration that every future hardware, administrative or accessibility
feature is complete.

## Architectural basis and actual starting point

The detailed comparison is in the proposal report.
The [source inventory](plans/source-map.json) maps all 43 preserved imports;
the [architecture index](ARCHITECTURE_INDEX.md) maps their responsibilities.

| Architectural requirement | Current accepted 0.3 | Required 0.4 change |
|---|---|---|
| F-001/F-003, U-010: human tasks and progressive responsibility | One bounded document flow; no actual layer controller | Useful desktop workflow and three real presentations over the supported objects/actions |
| E-010.5–6: datasets, normal folders and stable objects | Two fixed objects backed by separate fixed Store slices | A bounded user dataset, durable allocation and a directory/name catalogue |
| E-010.27–33: durable staged operations | Atomic 224-byte Read/Replace | Chunked larger documents and transactional namespace/data publication |
| E-016.14–16, E-009.4–8: selected-resource authority | Precise read/edit handoff for Notes/Private | Dynamic exact-object handoff, directory/create rights and correct rename/revocation behavior |
| E-017.25–26/.69–82: surfaces, Shell and focus | Fixed App/Shell surfaces and one App rectangle | Concurrent independently owned windows, focus, z-order and replaceable Shell policy |
| F-008, E-017.89–97: semantic accessibility | Flat generated document snapshot and named controls | Coherent semantic trees, authorized actions, assistive focus and a working semantic consumer |
| E-007, E-012, E-019: containment and recovery | App/Shell recovery and scoped signed App rollback | Qualified affected File/Block/Input/Display failure behavior and independent fallback |
| E-014/E-015/E-016, E-026.77–79: intentional native development | Internal frontend and tightly integrated Hello sample | Separately packaged native clients and a small documented SDK/build path |

## Reference targets

These are proposed engineering acceptance targets for this checkpoint, not
permanent architectural limits or a promise of unlimited capacity:

- At least 256 persistent workspace entries, including at least 32 directories,
  with nesting to eight levels. Names and contents are created by the user,
  not selected from a compiled list.
- Text files up to at least 1 MiB, with bounded chunked transfer, selection,
  multi-line editing and scrolling. Whole documents must not be placed on
  service stacks or copied into every semantic update.
- At least 64 MiB of usable workspace data capacity, with separately budgeted
  metadata, staging and recovery reserves. Retained committed revisions and a
  pending large Save must coexist, or the operation must be refused safely
  before acceptance. Total capacity and reserve boundaries are frozen at M8-01.
- Files, two independent Editor instances, and a settings/inspection window can
  coexist. Windows have separate owners, surfaces and routed focus.
- A sustained 30-minute actual reference session exercises creation, organizing,
  simultaneous editing, owner controls, cancellation and repeated reopen, with
  subsequent cold verification. This is distinct from human acceptance.
- Offline operation, verified existing 0.2/0.3 data, unchanged public promises,
  and explicit resource/admission budgets remain mandatory.

Measure the whole graph before broad UI implementation. M7's near-full handle
and frame cases are concrete warnings against merely appending more actors.
Choose bounded resource organization and a backend under the existing
governance. A target that cannot be met requires a recorded evidence-backed
revision and updated acceptance statement; it cannot silently become a PASS
at a smaller demonstration size. Numerical internal envelopes may evolve by
reviewed Level B decisions; authority, accounting and preservation guarantees
must remain intact.
Budget host space for builds, owned test volumes and retained original evidence
as well. Start each expensive qualification only with its declared space
reserve; previous disk-exhaustion failures must not recur through an unbudgeted
larger test graph. Preserve historical data and evidence.

## Required capabilities

### Durable workspace and larger documents

Define versioned dataset, object, directory and file contracts before adding
their UI. Specify stable identities and generations, enumeration, name/path
rules, create/open, rename, move within a dataset, reversible removal and
restore, allocation, quota/reservation and reclamation. Specify conflicts,
cancelled and uncertain operations, durable receipts, checksums and corruption
behavior. Existing read access cannot acquire create/edit/delete authority.

Use stable objects behind human-readable paths. Renaming or moving a file must
not redirect an existing capability to an unrelated object. A removed object's
storage or identity cannot be reused while an old grant could address it.
Directory listing is not blanket authority over its contents. Cross-dataset
and cross-device moves are separate until their copy/verify/commit semantics
are explicitly implemented and tested.

Qualify repeated allocation, trash/restore, eligible reclamation, reuse and cold
reopen. Interrupt allocation and reclamation as well as namespace publication.
Protect retained roots, live grants and restore data; recover abandoned staging
and reservations without stale-identity aliasing or a fabricated free-space
claim. Define when irreversible reclamation is eligible and what restore means
after that point.

Larger Save stages verified chunks outside the visible committed revision,
then atomically publishes the exact new revision. Report Saved only after the
declared durable confirmation and exact-content verification. Preserve accepted
operation identities across uncertainty; fence/quarantine shared buffers and
old writers until quiescence is established. Define serialized writers or
explicit stale-revision conflict detection for two editors; never silently
overwrite another editor's later committed work.

Preserve original File-v1/Store-v2 objects, private-note data, original volume
and object identities, valid durable remembered grant policy/revocations and
System content. Live per-incarnation edit grants retire on replacement and
require fresh selection; migration cannot resurrect handles or widen READ
policy. New schemas need an explicit compatibility/upgrade/rollback
plan. Unknown or corrupt metadata is never interpreted as an empty disk.
Retain original volumes and test migration on owned copies first. An old app
that cannot handle a new format must fail honestly without rewriting it.

E-010.26 permits a proven existing backend behind the contract. This checkpoint
does not require completing the ultimate native filesystem, nor may a host
directory, canned picker entries or shell commands impersonate guest storage.

### Native desktop, applications and input

Provide native Files and Editor clients with real package/contract boundaries.
The File/namespace implementation stays in userspace services. Root and the
kernel retain their authority/mechanism responsibilities; Files must not become
an all-powerful replacement Root. Reuse existing mechanisms where they fit.

Support window activation, keyboard switching, move/resize, z-order, scrolling,
close/relaunch and explicit modal ownership. Input targets the actual focused
surface owner. Apps cannot steal focus, read another window's input, spoof a
trusted prompt or draw over the protected control plane. Shell replacement
must preserve surviving applications and committed user state where supported;
dependency recovery must explain any operation that cannot continue.
Provide graphical checked shutdown/restart with explicit unsaved/uncertain-work
handling. Ordinary workspace use must not require the host terminal's diagnostic
`finish` command; keep that command available for its existing developer role.

Open, edit, create and Save As show distinct intent. A trusted picker resolves
actual current metadata and exact objects. Cancellation, requester replacement,
rename during approval, revocation and permission changes must not deliver
stale or wider authority. Selecting a name in an untrusted application is not
the approval event.

### Three responsibility layers with real effects

| Layer | Required supported workspace behavior |
|---|---|
| 1 — Simple / Automatic | Create, find, edit, save and recover through task-oriented controls, safe defaults, plain status and useful next actions. The user need not understand the process graph. |
| 2 — Advanced / Full Control | Inspect actual app/file access, running work and measured resource use; change supported permissions/preferences; stop/relaunch an app and inspect a failure through explained, reversible controls. |
| 3 — Absolute Access | Enter a protected deliberate owner interaction, inspect deeper actual state, and perform a consequential supported manual delegation/revocation or override that ordinary policy would refuse. The exact target, rights, consequence and recovery route are explicit. |

Layer 3 needs a real trusted-attention/input boundary and actual authority
effects. It cannot be three labels, a hidden debug flag, a serial command, an
unchecked security bypass or ambient root. Qualify at least one supported
owner override end to end: ordinary refusal, deliberate owner authorization,
the exact changed capability effect, unrelated resources still confined, and
revocation/return to ordinary operation. A declaration or signature alone
never supplies authority.

The trusted inspection/recovery route must remain reachable when the normal
Shell or an App is unhealthy. Keep it small and separate from ordinary desktop
policy. State its supported VM owner/presence model honestly; this checkpoint
does not certify multi-user enrollment or firmware-to-human authentication.
Unsupported kernel/driver/boot operations must be identified as future work,
not hidden behind a claim of complete system-wide Absolute Access.
Test actual trusted attention with the normal Shell blocked and with it dead.
Verify protected presentation/input and reject forged, stale or replayed App
and ordinary Shell requests to enter or confirm owner actions. Merely reaching
a recovery boot does not qualify this live trusted-attention boundary.

### Accessibility and understandable state

Expose versioned, coherent semantic trees for Files, Editor, window management,
pickers, layer controls, errors and recovery. Include stable node identities,
labels, roles, values, state, bounds and supported actions. Semantic commits and
displayed state must correspond to the same actual model revision. Large text
uses bounded range access; tree snapshots carry no authority by themselves.

Provide a real authorized semantic consumer/navigator and action path across
process boundaries, including refusal/revocation tests and distinct assistive
focus. Keyboard-only operation must complete the same supported workflows as
pointer operation. Provide usable scaling/contrast, visible focus, non-color
status and motion preferences for first-party surfaces.
Define the authorized assistive confirmation route through the same protected
picker/owner consent boundary. Reading a semantic tree or possessing ordinary
semantic Activate authority cannot approve access or a Layer 3 action. Qualify
fresh confirmation, stale presentation, revoked authority and assistive-provider
replacement; the trusted workflow must remain accessible through the declared
supported route. Report any unavailable action honestly rather than treating
unimplemented protected consent as an accessibility PASS.

Declare actual text input, font/glyph coverage, Unicode handling and assistive
providers. Preserve unsupported bytes. A semantic test consumer is not a speech
screen reader; speech/audio, full international IME and broad assistive-device
coverage need their actual implementations and separate evidence.

### Failure recovery and compatible lifecycle

Specify a dependency/failure matrix for App, Shell, File/namespace, Block,
Display and Input, covering both death and timeout with in-flight operations.
CPU death alone is not device, DMA, mapping or shared-window quiescence.

Qualify actual File/namespace and Block failure during the new workspace flow:
fence old writers, establish device/window retirement, restart/reopen or enter
independent recovery, and inspect durable state without repair writes from the
observer. A generic fail930 or a test that changes only an App is insufficient.
Display/Input loss needs a bounded recovery/fallback route with no cross-owner
input leak or dead trusted confirmation. Keep any unsupported restart case
explicit and make its independent recovery route an actual acceptance test.
Death and timeout need distinct actual qualification where supported by the
matrix. Include deliberate owned-VM cuts around new allocation/reclamation,
directory publication and large-file staging/publication, followed by independent
cold decoding and exact content/namespace checks without host repair. Qualify
interrupted migration/resume too if a migration is implemented. Earlier 0.3
cut evidence cannot qualify these new persistent mechanisms.

After a genuine good App version becomes healthy/Known Good, save later larger
documents and namespace changes, fail a later candidate, recover offline and
reopen those same objects. Keep package code, datasets and recovery state
separate. Existing signed App rollback does not qualify arbitrary common-Root
reconstruction. Actual loss of the common supervisor must at least preserve
data and have a tested independent recovery boot for the supported cohort;
in-place Root/device graph reconstruction is not inferred from that cold proof.
General Kernel/Root image replacement remains a distinct future scope.

### Developer path, build discipline and performance

Document an external sample's create/build/package/verify/run/install path using
generated contracts and the `ev` frontend. It must not copy private Root layouts
or depend on Rust implementation ABI across process boundaries. Demonstrate
granted and refused resource access, private data ownership and failure
reporting. Keep Internal/Preview labels honest; Stable needs compatibility
tests and the prescribed lifecycle.

Record Board/Product/Profile inputs, bounded action dependencies, tool and
firmware identities, declared environment and output hashes. Demonstrate a
clean provisioned build path without transplanting prior Evrosion targets and
compare complete target artifacts across two declared Linux build contexts.
After the declared acquisition/bootstrap step, actually build/package the OS
and the independent sample with network access disabled, using only declared
verified tools/dependencies. Retain pinned-input/action/output records and name
remaining EXC-0002 host dependencies; another warm-cache comparison is not the
required provisioning/offline-build proof.
Account for E-014 explicitly through an ADR and replaceable orchestration behind
`ev`; nested Cargo and prepared caches alone are not a hermetic OS build proof.
Production release CI, remote execution and distributed caches remain separate.

Measure stack/image/frame/handle/queue/storage budgets, repeated resource
retirement, contention, input/Save/tail response and failure/replacement overlap.
Use one Job/accounting model. Preserve the known historical IPC cost and make
new comparisons with matching observers. Reject an over-budget graph honestly;
do not remove checks to make a larger desktop fit.

## Gates and proof

| Gate | Required completion result | Evidence |
|---|---|---|
| M8-01 | Architecture delta, contracts, compatibility and resource plan | Source-linked ADRs, generated schemas/bindings, frozen dataset/staging/recovery capacity, initial linked admission and host-evidence-space review; preserve foundations and imported sources |
| M8-02 | Multi-object dataset and durable namespace | Actual guest create/list/rename/move/trash/restore/reclaim/reuse, interrupted allocation/publication/reclamation, stable identities and independent cold inspection |
| M8-03 | Larger transactional files | Actual multi-chunk read/edit/Save, 1 MiB target, staging/publication VM cuts, stale-writer conflict, full-space refusal, cancellation and uncertain completion |
| M8-04 | Dynamic trusted resource selection | Actual exact-object/create rights, fresh input and requester identity; READ/rename/revocation/stale-selection negatives |
| M8-05 | Concurrent native desktop | Files, two Editors and inspector/settings coexist with separate surfaces, correct focus/modal routing, move/resize and independent close/relaunch |
| M8-06 | Three responsibility presentations | Real L1 tasks, L2 controls/inspection and protected deliberate L3 action with scoped authority effects; actual trusted attention and forged/stale entry/confirmation refusal |
| M8-07 | Semantic accessibility | Coherent trees, authorized cross-process consumer/actions, assistive focus, protected assistive confirmation with stale/revoked/provider-replacement tests, keyboard-complete workflow and visual preferences |
| M8-08 | Affected-service containment and recovery | Actual supported File/namespace/Block death and timeout plus Display/Input fallback; old-writer/device/window fencing and independent durable-state inspection |
| M8-09 | Preservation and lifecycle composition | Original 0.2/0.3 bytes, identities and valid remembered policy preserved or explicitly migrated with originals retained; no live-grant resurrection; healthy App, later edits, bad update and offline recovered reopen |
| M8-10 | Independent trusted recovery | Shell blocked/dead cannot suppress protected owner interaction; common-supervisor loss preserves data and reaches tested independent recovery boot; graphical checked shutdown/restart |
| M8-11 | Intentional native SDK/client path | Independently packaged client builds and uses generated contracts, exact grants/private data and structured failures through documented `ev` commands |
| M8-12 | Reproduction and resource/response qualification | Two declared clean/provisioned build contexts, actual post-bootstrap network-disabled OS/sample build, whole-file comparisons, affected optimized linked budgets, contention and retirement tests |
| M8-13 | Sustained usable session | Actual 30-minute reference interaction, complete cold reopen and owner guide covering full workflow; human feedback recorded separately |
| M8-14 | Qualified integration and current project state | Guarded adoption, retained preimages and source history, regressions, current architecture and implementation notes with recorded qualification results |

No item closes on models, Ready, screenshots or a policy declaration alone.
Use source/artifact-pinned actual processes, capability delivery, persistence
and recovery evidence. Host models complement actual VM faults and do not
establish physical power-loss coverage. Retain failed attempts and original
captures. Preserve unrelated data, previous acceptance and the source history.

## Execution sequence and integrated acceptance story

1. Freeze 0.3 and record the actual starting bytes. Review architecture delta,
   storage/namespace migration, surface/input/semantic/owner-control contracts,
   graph capacity and device/failure ownership before expanding the graph.
2. Implement and qualify durable namespace, larger-file operations and exact
   dynamic grants. Keep the existing reference/old clients available.
3. Build Files and Editor clients and concurrent desktop behavior on those
   contracts. Add three-layer controls and accessibility in the same increment.
4. Compose real affected-service recovery, trusted fallback, compatible App
   lifecycle and independent owner recovery. Verify all committed user data.
5. Complete SDK/build reproduction and sustained-use/resource/failure
   qualification; exercise the walkthrough, present it for owner feedback and
   record actual feedback or pending status. Complete qualified integration
   and update implementation status. Engineering exercises supply no human acceptance.

The final end-to-end scenario creates `Documents/Ideas`, creates and edits a
multi-page file, opens another Editor, exercises focus/window controls, renames
and moves an object without changing its identity, performs a deliberate scoped
owner permission change, accesses the same state through a semantic client,
recovers supported service/App failures and reboots. Independent inspection
must find the intended committed namespace and exact bytes, including later
edits after failed-update recovery, while old 0.2/0.3 data stays preserved.

## Preserved future commitments and selected boundary

The target remains an owned x86-64 QEMU development reference. The accepted
physical deferral is unchanged. No personal-disk installation, physical boot,
official signing or publication follows from selecting this goal.

Production-scale native filesystems, external/network filesystems, cross-device
moves, complete encryption/backup/scrubbing, full GPU/media/browser stacks,
complete international input or speech accessibility, general multi-user
enrollment, general Kernel/Root replacement, broad hardware qualification,
consumer installation/migration, bundled Windows compatibility and AI remain
separate scopes. Their accepted architectural obligations remain binding;
native use must not acquire mandatory foreign-runtime, cloud, account or AI
dependencies. This checkpoint is a substantial step toward the native platform,
not all of E-026 Era C or consumer 1.0.

## Short implementation goal for owner selection

> Build and qualify Evrosion 0.4's recoverable native desktop: real files and
> folders, larger documents, multiple windows, deliberate three-layer controls,
> semantic accessibility and service/update recovery, preserving existing data
> and capability guarantees. Follow the recorded M8 plan and keep project state current.
