# Workspace service

`ev-workspace-service` is a safe `no_std` File@2 gateway over the real
`ev-workspace-store::Dataset`, registered in the isolated M8 workspace. Its
`native-actor` feature builds the actual V5 executable over the Block workspace
Region. Host integration, bare linking and ELF preflight do not establish VM
qualification or complete the Files/Desktop implementation.

The trusted native adapter supplies a captured endpoint identity/generation,
actual caller process/incarnation, current lease epoch and actual monotonic time.
Root's separate owner API installs/revokes at most eight route rows. Each row
fixes one actual File object/generation and ReadOnly or ReadWrite authority;
ordinary wire data cannot install a route, select another object, invoke a raw
sector/global-operation selector, reclaim an object or fabricate a ReclaimFence.
Same endpoint/caller lease epochs cannot regress or be reused. The actual grant
and endpoint retirement remain kernel/Root adapter responsibilities.

Client mutation nonces are scoped to that full actual route/caller/lease. Their
canonical request and chunk fingerprint is retained per row, while global
durable operations are allocated only from `Dataset::next_operation`. The
backend's 16-byte correlation scope hashes the full captured caller/incarnation,
endpoint/generation and Root lease. Each trusted bind additionally freezes the
current durable `Dataset::next_operation` as its private backend lease scope.
After any prior mutation that monotonic value advances, preventing repeated cold
PID/endpoint/Root-lease1/nonce1 values from aliasing a prior durable receipt.
Binding without a mutation creates no earlier receipt to alias. This backend
scope is allocated only by the service and is never a wire operation selector.
This hash is correlation metadata, never authentication. Two Editors may both
use nonce1 without sharing backend operation IDs. A repeated exact latest
request can return its original receipt; changed fingerprints conflict and older
nonces refuse without reexecution. Cold boot does not magically reconstruct
this volatile per-route replay cache. Missing history is not nonexecution.

Read checks the exact revision and copies verified bytes into caller-resident
private scratch before publishing the range. Begin/WriteChunk/Commit check exact
revision, stage ownership, ordered offsets, declared lengths and SHA-256 values.
Opaque transfer tokens map to private backend stage IDs and never authorize a
different caller/route. Commit uses `CommitVerifier`: one 4096-byte verification
step per trusted `poll_commit`, then a separate exact metadata publication.
The admitted original deadline is retained throughout; no tick or Query renews
it. Final metadata publication still needs actual target timing qualification.

`Dispatch::Complete` distinguishes definitive pre-I/O refusals and exact
completed service results. `Accepted` and `Retained` do not acknowledge return
of a shared-memory loan. The adapter must hold the actual 2-page File control/
bulk window and protected RPC nonce until matching complete reply/credit return
or proven quiescence. I/O errors, corruption, unknown completion and deadline
expiry after acceptance retain the exact request, operation mapping and private
snapshot; they cannot become a normal reply or trigger a new-ID retry. Revocation
blocks future requests but cannot retroactively undo an accepted operation.

Dataset Scratch (currently53,760 bytes), service Scratch (4096 bytes), route and
verification state must be owned resident allocations, not catalog/document
stack temporaries. This core raises no kernel capabilities, limits or rights.
Its workspace region is152,322 relative sectors; backend/device-window ownership
and exclusion of legacy regions must be established by the actual Block adapter.
New-data provisioning and interrupted-mirror recovery are explicit owner work
before ordinary admission, never an implicit format/recovery fallback.

Two separate namespace rows fix a directory generation and Inspect or Manage
rights. Generated Workspace@1 handles actual Create/List/Inspect/Rename/Move/
Trash/Restore, including one atomic restore-at with destination and name. List
returns one dynamic resident entry and next slot cursor at the exact namespace
revision; it includes reversible trash metadata with effective state. All object
and destination selectors must remain inside the admitted directory. Namespace
management never installs File READ/EDIT, selects a content endpoint or exposes
purge/reclaim. Directory limits, name96-byte UTF-8, depth8 and256 child slots are
backend-enforced. No ordinary wire request can permanently remove/reuse a slot;
actual Root revocation and quiescence remain prerequisites to adding that path.

Namespace mutations use their own domain-separated authenticated client scope,
durable bind epoch, full original-frame fingerprint and serialized global ID.
Unknown publication retains the original frame/global mapping, fences all fresh
mutations and refuses storage extraction. Replaying an accepted request after
its original deadline remains retained for both protocols. Expiry cannot become
a normal Cancelled completion after acceptance.

The native actor parses exact V5 child528 and sixteen role grants. It negotiates
ServingOrigin57/INFO58 and captures the currently accepted receiver/nonce,
process/thread, registered token, endpoint, call epoch/serial, original deadline
and status before any shared frame access. RECEIVE_RPC34's RDX is never treated
as an origin. Role16 independently admits only Root SEND; role10 admits only
Files namespace SEND. Their static actual endpoint admission supplies permission;
the recorded first actual origin supplies correlation, not Root authentication.
Role11..14 File routes additionally match Root-bound process/token/thread and
lease. No identity is trusted from the request body. All scalar RPC payloads
correlate the entire64-bit request ID with the control frame.

Strict Root `control::{Request,Command,Response}` Bind/Revoke on role16 checks
the current explicit DatasetId and exact slot/lease. Successful Bind publishes
SDK Selection metadata from the live route and actual durable file metadata into
the selected caller's window before Applied. Failure revokes or quarantines;
Selection alone never grants authority. Root's independent inbox transfer must
carry the same request ID and actual File SEND. Before a new/replacement bind,
Root must establish all uses of that window quiescent: Files namespace and its
File route share the Files two-page window. Revoke neither retracts an accepted
operation nor establishes loan return. Ordinary routes cannot issue control.

Root-only recovery adds `ReconcileFile` with the exact old process/thread/token,
lease and original32-bit grant nonce, plus `ResetFilesNamespace` for the retained
Files session. Root constructs its private retirement receipt from actual Kernel
facts before issuing either command; the wire fields are only correlation. A
logical Revoke now retains the installed old row and cannot make its window
available to Bind. Successful reconciliation requires no pending file/namespace
request or Commit verifier, aborts only a matching known abandoned stage, waits
for actual backing flush and clears that exact route. Per-slot lease floors
survive retirement; wider Bind IDs refuse before installation rather than
truncate Kernel44. Any accepted failure/uncertainty remains fenced. A cold orphan
stage is preserved for independent recovery, not guessed to belong to a new app.

Namespace reset retires only the old exact retained namespace key after actual
old caller/endpoint retirement. It neither clears the Root namespace nor grants
file access. If Files died before its first request, explicit Root reset can be
a no-op only with no pending/fenced work. The dedicated Files SEND still limits
the subsequent caller. The service's existing quarantine loop does not process
new recovery control after unknown accepted execution; that case requires actual
independent retirement/cold recovery. These APIs do not imply hot failure recovery.

The actor copies frames/chunks into private residents, retains the actual serving
RPC nonce through Commit continuation, and checks that exact call still live
before publishing a completion. Each verification poll yields and preserves the
original deadline. Unknown execution, expired/cancelled accepted work or failed
reply credit puts the actor into permanent retained quarantine; only independent
Root/kernel/device retirement can recover ownership. It never auto-retries with
a fresh ID, fabricates a successful cancellation or reconstructs an unfenced
writer. Normal startup performs metadata-only open without format/write-repair.
The separate `provision-new` measured feature scans NEW-only blank storage with
bounded prehealth continuation; it must not be admitted as normal Ready while
provisioning. It seeds no compiled file list.

Focused host tests use actual generated codecs, the Editor engine, Dataset and
a flush-aware SectorIo memory device. They cover a full1MiB Save/readback/cold
exact-byte result, bounded Commit continuation, independent nonce1 clients,
replay/conflict, READ refusal without storage I/O, stale/revoked routing,
malformed controls and I/O-after-persist uncertainty with retained snapshots.
Namespace tests exercise real wire CRUD, atomic renamed restore, cold dynamic
listing, fixed directory scope, readonly refusal before I/O, cold repeated
identity/nonce, maximum entry/depth/name bounds, and retained accepted failures.
`tools/qualify_native.py` canonically strips debug information with pinned
llvm-objcopy, checks exact entry and loaded bytes/flags/lengths/addresses and
counts all LOAD pages including the exact guarded32KiB stack480..487 against
the96-page profile. Canonical stack_audit supplies a fixed-frame census with
its explicit raw assembly/recursion/runtime limitations. Exact live grants,
shared-window/device retirement, timing, cuts and actual VM acceptance remain
separate gates. No legacy File-v1/Store-v2 volume is opened or migrated here.
