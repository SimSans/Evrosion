# ADR-0099 — Protected owner first-use preparation

Status: Accepted Level B policy in private components; final joined resources and
actual first-use/cold qualification remain pending.

## Problem

A fresh owner workspace could install bundled A without executing it, fetch B,
and select B for its next managed boot while the separate Note namespace was
still blank. Managed startup deliberately performs readonly preload and allows
only retained, authenticated no-IO probation reads. A missing Note therefore
cannot become a successful Read, saved frame or Critical signal during health.
Requiring an undocumented initial Hello launch avoids the gap but adds a setup
ritual to the normal owner update path.

The isolated signed-Store audit reproduced selection followed by an authenticated
Stale probation Read with no body or fallback IO. This was a model of the gap,
not an actual guest health result. Preserve that audit, the readonly guard
component, the original 224-page admission refusals, and all failed cold runs.

## Decision

Treat explicit owner Fetch and explicit next-boot selection as consent to create
only their genuinely new required namespaces. This adds no App entry point or
network authority. The existing current live Shell authentication, settled
presentation, fresh input and single-use request gates remain mandatory. The
protected owner command line reaches the same State preparation rules.

Before content provisioning, network Fetch or replay publication, Fetch may call
unchanged protected-A installation only when State holds its private observation
that the complete Registry and AppData regions were blank. The closed graph's
single serialized backend and exclusive owned Host disk are part of that credit.
Each existing format_new still checks its own whole region before writing.
Installation writes and reads back the initial scalar and Registry publication;
it stages A without starting App code. Missing metadata alone, a tombstone,
corruption, an unresolved owner or an uncertain completion grants no creation
permission. An already installed compatible baseline is retained.

Before System initialization, stage or activation, Root resolves the exact
checked downloaded cohort it would publish. Activation uses the actual System
staged manifest rather than assuming Registry active/staged names the same
candidate. A move-only StartupSelection contains the actual current Registry
revision and that candidate package digest. State independently checks the
fresh full Registry head and current checked Downloaded Source. The candidate
and Registry head bind separately: legitimate B selection can occur while A is
the Registry's current installed source.

Fresh readonly Registry, scalar/schema and Note inspection remains the selection
gate. A valid existing Note is preserved. Only an Unformatted Note whose entire
actual region passes the blank scan may enter the shared ordinary Note creation
helper. It uses the existing stable App/schema namespace manifest, typed empty
initial envelope, format_new, full validated manifest/body readback and exact
initial-body comparison. State invalidates any older preload receipt before
creation. It then performs another genuine readonly prerequisite check before
the separate System journal mutation.

This trusted preparation creates no App request or successful Read, consumes no
App nonce, and fabricates no Present, Critical, health receipt or KnownGood. The
initial Note envelope has counter 0; an admitted App's nonce ledger remains 0
until its own real request. Its later Read must still use the existing
nonzero-nonce client/Root protocol and actual body checks. No App is stopped or
started by preparation, and an ordinary live A may remain admitted.

Preparation, readback, final readonly inspection and the selected System action
share the caller's original native-session storage cut of 8192 ticks. Existing
nested child RPC/IO cuts of 1024/512 and producer output cut 512 remain unchanged.
No accepted IO is replayed or given a renewed deadline. Probation refuses setup
before IO and retains its existing authenticated Busy and no-IO read rules.
Partial creation/publication is preserved; an uncertain or corrupt outcome
fences the owner rather than rolling back, retrying format or replacing data.

## Presentation and retained sets

Add internal Update code 9, SetupRequired, within the existing four-bit field.
Codes 0–8, Request version 1, eight-byte bodies, Note/scalar schemas and stable
App contracts retain their meanings. Values 10–15 remain invalid. Root, Shell
and graphics are built as a coherent source/image set. Setup is a cached UI
hint, never creation or selection authority. Root's transient presentation
context additionally binds the current Registry revision, setup state, actual
Shell scope and exact candidate; an old settled gesture cannot survive a change.

The setup view says “Ready for first use.” It enables online Fetch with no
candidate, or Use after restart with an actual candidate. It does not enable
Restart. Opening Hello remains an ordinary option, not a prerequisite ritual.
A clean missing prerequisite does not itself latch recovery; unknown or corrupt
state must not be mislabeled as a verified blank setup case.

Host boot-set schema 2 identifies this unreleased first-use policy boundary.
Existing schema-1 sets, their media, owner records, artifacts and downloads are
left untouched and refused with their locations and explicit recovery guidance.
There is no migration, rename, format, publisher-pin change or replay-floor
reset. New Host code does not claim an old retained Root has this correction.
Within a compatible retained set, authenticated restart still requires actual
RS1, full normal Kernel/physical retirement, fresh post-exit serial and the same
readonly selected manifest before reusing its exact boot set and owned disk.
V4 capacity metadata is a separate refinement in [ADR-0098](ADR-0098-measured-v4-owner-capacity.md);
this preparation adds no syscall or capability route.

## Validation and limits

State models exercise real signed sources and Store creation/readback, separate
head/candidate binding, genuine blank-only creation, preserved existing work,
partial failures, stale receipts, ordinary live A and probation zero-IO/nonce
rules. UI models cover code 9, applicable actions, reserved values and fresh
settlement after setup/head changes. A Host model preserves and refuses schema 1
before artifact loading or disk writes. These are not guest timing evidence.

The separate finite owner-ui-first-use-probe route uses only new owned media and
real QMP/PS2 controls. Its standalone phase must show no App lifecycle or captured
App slot, Fetch with Note/System still wholly blank, explicit selection with
actual empty Note counter 0 and selected B, default Cancel with zero RS1, then
fresh confirmation and full normal retirement. Its offline cold phase requires
actual initial empty Saved B pixels, protected Read, current healthy admission,
full durable probe, System KnownGood, content KnownGood and checked Finish.
The existing dirty-buffer/Busy/save/live-App/cancel qualification remains
separate. Manual cargo ev network never invokes either scripted observer.

Final acceptance needs a reviewed joined source, fresh actual mode resources and
startup mechanism qualification. The original 600-second observation and all
operation, health, shutdown, scheduling and ownership limits remain in force.
