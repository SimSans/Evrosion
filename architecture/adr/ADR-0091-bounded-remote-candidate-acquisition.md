# ADR-0091 — Bounded remote candidate acquisition

Status: Accepted Level B implementation refinement; actual image admission and joined guest acquisition remain pending.
Date: 2026-11-13.

## Decision and scope

An exact authenticated owner `update-fetch` command may acquire the single
Hello development target through the actual Root-only network and content
owners. The fixed peer and paths do not select an authority: the independent
ROM Root and logical target binding do. Source controls retain Standalone's
System mutation refusals. Acquisition, executable registration, Registry
selection, probation and Known Good remain distinct.

The resident Update first borrows the exact Backend and authenticates its
current content namespace. A genuine current Registry selection is reconciled
before a replacement can erase a sole candidate. No open failure formats,
initializes replay state or selects a replacement Backend. The same private
4KiB chunk and IO/Cold/Commit owners continue through all phases.

Timestamp, Snapshot and Targets are bounded private transport inputs. Their
raw links choose only bounded expected bytes, never authority or a destination.
Before any metadata Arena write or permanent artifact image allocation,
Preparation verifies the current Root, threshold signatures, exact links,
retained replay floors and the fixed single target with fresh actual qualified
clock callbacks, including one after crypto. Preparation changes no replay
state or floor, authorizes no execution, and creates no persistence Decision.

Actual immutable object reservations precede accepted artifact bytes. A network
chunk remains unchanged until its exact storage write succeeds; an unknown
write keeps the same owner and chunk without transport acknowledgement or
retry. Every object is fully reread and hashed through the canonical Reader.
The artifact streams into the real image-control writer and passes Seal/Verify
as unregistered immutable preparation. Metadata preflight prevents an invalid
signature peer from consuming permanent sealed image slots. Full Zion/App,
package/build/source/schema and independent descriptor checks remain mandatory.

A second, separately defined fresh private time exchange precedes full candidate
authorization. Both phases use the same private temporal adapter and actual
Store-bound callbacks; no chosen nonce, clock model, author timestamp or floor
fallback is supplied by acquisition. The final callback authorizes the exact
head, references, replay proposal and floor. Later IO completes that affine
decision; a delayed durable ACK or activation is not new UTC authorization.

The existing resident Commit holds prepared authorization output. A private
binding distinguishes it from empty or IO-owning phases. Consumption rechecks
the same head/revision before the canonical record/Cold/Commit path. Occupied
workspaces refuse replacement. Failed crypto exposes no prepared decision.
Explicit discard applies only to prepared metadata with no actual IO owner;
it cannot discard Checking/Writing/Reading/Published work or clear a fence.
The older consuming APIs delegate to the same verifier and commit logic.

Only actual checkpoint publication and the full package association permit
Register. A local Member then binds exact Content, the unique Images owner,
registered capability and permanent read-only header. The same registered
member is adopted into local resolution before the exact Backend returns and
Registry Stage publishes that candidate. NR25 success acknowledges this staged
result. It does not activate an App or create health/Known Good.

## Selection, local identity and failure

Explicit Activate keeps held-image-before-Registry-commit ordering. After actual
startup and UI settlement, downloaded selection is persisted through the same
exclusive Backend, authenticated Store and canonical Commit before final owner
success. The move-only Registry receipt binds actual record, private backend
identity and nonwrapping loan sequence through consumption. This changes only
selected retention, never health or Known Good. A cut before that publication
still retains candidate B; every later fetch must reconcile actual selection
before C can replace it. It refuses a replacement that would strand selected B.

Volatile registered Member receipts keep already-authenticated local provenance
available after newer candidate membership changes. They cannot manufacture a
current Store, remote floor, durable reference or new authorization. State's
actual busy/recovery/poison guards continue to deny data IO while its Backend
is away or uncertain. Clean signature/time/policy refusal can return only the
same actually quiescent healthy owner. Unknown IO or clock uncertainty retains
the original owner and all fences. Publication and cancellation stay distinct.

The first implementation refuses owner Cancel as busy while a remote exchange
is active; it does not claim cancellation or release an accepted time/network
loan. Finish likewise waits for the actual remote operation to settle. Disk-only
cancellation retains its existing semantics and original operation cut.

## Bounds and evidence

A new whole fetch class captures 2^21 PIT ticks once: the existing 2^20 Inspect
bound plus four at-most-65536-tick downloads and bounded readback, image and
publication work. Each download retains its own original cut and at most2048
actual network calls, with paced Pending polls. Actual RPCs remain at most1024;
metadata operations remain at most8192. Each proof is independently clamped to
its own8192 limit and the original fetch cut. No CPU quota, frame array or stack
size changes. The data model needs no second Snapshot, heap, self-reference or
full-artifact Root buffer.

Tests drive the actual Store, transport codecs, acquisition continuation and
Images continuation over model devices and explicit synthetic test clocks.
They check preflight-before-resource-consumption, full readback/seal before
final authorization, journal publication before Register, unchanged active/Known
Good, occupied/stale decision output, post-crypto refusal and exact workspace
reuse. They do not establish a guest clock, physical mapping or M6 acceptance.

Actual linked component evidence and resource experiments remain separately
retained in the local engineering archive, including the original
size experiments. The first joined image refused176 pages and its stack also
refused32KiB. Resident authorization and separate construction frames remove
large automatic result slots; direct terminal Backend extraction avoids carrying
discarded Snapshot bytes through cancellation. Broad inlining experiments were
rejected for code growth. No failed image is admitted or relabelled successful.
Fresh exact image, selected Kernel and retirement census precede any guest run.


Current M6 scope clarification (2026-11-13): the Standalone System-mutation refusal above describes this ADR's initial acquisition-only profile. [ADR-0092](ADR-0092-downloaded-cohort-health-and-retained-authorization.md), [ADR-0099](ADR-0099-protected-owner-first-use-preparation.md) and [ADR-0100](ADR-0100-versioned-downloaded-cohort-startup-policy.md) add explicit protected owner preparation and System selection with versioned downloaded health. Fetch remains separate from selection/activation: these refinements introduce no automatic App activation or old-format fallback.
