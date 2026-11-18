# ADR-0104 — Bounded workspace dataset and durable namespace

Status: Accepted Level B portable implementation direction; target/service/VM
qualification pending. Date: 2026-11-15.
Related: M8-01–04/08–10/12–13; E-009.4–8/.30; E-010.1/.3/.5–10/.26–33/.38–39;
E-012.20–25; E-019.24–31; ADR-0043/0044/0045/0049/0102/0105.

## Decision

Implement `ev-workspace-store`, a safe `no_std` userspace storage backend over
the existing `ev_store::SectorIo`. It operates on one explicitly owned NEW
region, independently of every original File-v1, Store-v2, package, grant and
private-note region. It neither migrates nor reformats these formats. The
trusted Block adapter must enforce the region before this backend is admitted.
No numeric sector, dataset ID, object ID or fence struct is kernel authority.

The reference supports an implicit root plus256 dynamic objects, up to32
dynamic directories and eight levels below root; UTF-8 byte-exact names have
at most96 bytes. Individual files contain up to1MiB.64MiB of4KiB-rounded
committed allocation is available, including retained trash, with an additional
2MiB physical staging reserve. Checksummed chunk headers and metadata increase
the complete owned region to152322 sectors/77988864 bytes. This region must be
assigned without overlapping existing data. These are bounded engineering
envelopes, not permanent consumer limits.

Use two512-byte roots and two streamed64KiB catalogs. A mutation writes the
inactive catalog where necessary, flushes and reads it back, then publishes an
alternate checksummed root. That first confirmed root is the atomic boundary.
Before acknowledging, mirror and verify the same root in the other slot. One
later bad root therefore does not silently revert an acknowledged document.
Checksums detect damage; there is no claim that two catalog banks are general
redundancy or that lost file data can be repaired without another valid copy.

Every occupied slot has a nonwrapping generation and stable identity. Human
names and parents are metadata. Rename/move do not change file identity or
content revision. Trash retains the object, bytes and descendants; restoring a
directory makes its retained subtree visible again. Purge applies only to a
trashed file or an empty directory, after a trusted owner has fenced grants and
established necessary quiescence. Vacant slots retain their generation; reuse
increments it, and old identities fail before data I/O. Trash is a retention
root and cannot be reclaimed merely to make free-space figures look better.

There is one durable staged writer per dataset. Begin records an independently
allocated extent, target generation, expected revision, exact length and SHA256.
Canonical4KiB chunks (except the final shorter chunk) are written, flushed,
header-published and read back before advancing the durable offset. Commit
verifies every chunk and the exact full-file digest before atomically switching
the catalog reference. Old committed content stays visible until that switch.
The same file's stale editor is refused. Other editors retain their own data;
they serialize staging or receive Busy, never silently overwrite later work.

## Operation identity and uncertain execution

The serialized trusted owner allocates backend global operation IDs using
`next_operation()`. A wire operation is a different, per-authenticated-client
nonce. Two Editors may both send operation1. The service derives a
`ClientRequest` from actual caller/incarnation and lease, attaches its client
nonce with `OperationId::for_request`, and retains its mapping while processing.
It must never reinterpret a packet nonce as a backend journal selector.

The LAST root receipt retains this exact authenticated identity/lease/nonce,
the backend global ID and a full canonical request fingerprint. Same global ID,
same bound caller and same fingerprint replays without I/O when both mirrors
already match; interrupted mirroring finishes before a replay ACK. Another caller's
same nonce conflicts. An immediate duplicate client request cannot become a
fresh global mutation. Older global IDs return StaleOperation after eviction.
This is LAST-receipt retention, not unlimited exactly-once history or a durable
per-client replay table. Service adapters must retain earlier unresolved
ownership/mappings, or expose Stale/Uncertain and recover explicitly. They may
not manufacture nonexecution, reuse a loan or issue a fresh ID after eviction.

Any backend I/O error poisons further access. Failure may have committed; the
same physical region may reopen only after old writer/device/window quiescence.
Cold open performs130 reads only, validates roots/catalogs/graph/extent references,
retains incomplete staging and resolves the LAST operation from durable state.
It does not flush, repair, format, roll back a damaged newest valid reference or
discard partially provisioned data. Partial NEW setup remains explicit and
requires explicit owner recovery; format-on-open-error is forbidden. Data chunks
are checked before delivery; full content scrub and staged-checkpoint validation
are explicit work, not a hidden64MiB startup scan. A sole good root is retained
while its invalid/outdated peer is repaired first, with fresh mutations fenced.

Provisioning runs before ordinary desktop/cohort health. `Provisioning` scans
the new owned region in bounded caller-driven steps with separately captured
deadlines. Only after all sectors are confirmed blank does it durably publish
NEW-only `EVWPRV01` markers and create metadata. Explicit resume requires the
same expected DatasetId and checks the untouched data area before completing
metadata. A torn first marker with no valid copy stays preserved for owner
action; it never licenses erasing unidentified bytes. Full cost and target
budget obligations are in the design, including the synchronous helper's limits.

Full-file commit verification also has a private small `CommitVerifier`
continuation. Verify at most the requested chunks per captured deadline, then
publish only if the exact dataset/stage is still current and its complete digest
matches. It is RAM progress, not a durable operation receipt or authority.

## Resource organization and limits

Catalog and4KiB verification buffers live in a caller-owned resident `Scratch`.
Open/format borrow that owner; no catalog or full document is returned on the
stack. Enumeration returns one small metadata record and names borrow resident
storage. Data passes through bounded caller buffers. Actual target placement,
stack census, grants, routes, scheduling, cancellation and lifetime evidence
remain required; a Rust value or portable memory test establishes none of them.

This first allocator uses contiguous4KiB chunk extents and no compaction.
NoSpace can therefore describe fragmentation as well as quota exhaustion.
Reserve is not ordinary allocation quota. Abort releases only its separately
staged extent after serialized ownership is safe. Retained catalog objects,
trash, current staging and their identities remain roots; object purge/reuse
requires the exact current namespace revision and an external owner fence.
The documented fence epoch is an integration assertion, not proof of revoked
capabilities or hardware stop.

## Verification and remaining acceptance

Focused host tests use actual SectorIo reads, writes, volatile caches, flushes,
readback, before/after errors and173-byte torn sector writes. Cold reopens use
another owner with volatile state discarded, verify exact old/new bytes and
retry the original operation. Tests cover full64MiB allocation plus1MiB
replacement staging, bounds, trash/restore/purge/reuse, stale identities and
writers, scoped client nonce collisions, corrupted bytes and read-only refusal.
Retain command receipts and failures; the initial test compile failure and
corrected focused runs are distinct evidence.

This is portable host storage evidence. M8 remains open for actual File/Block
integration, authenticated client mapping, grant/reclamation fencing,
source-pinned VM failure/timeout/cold recovery, multi-window editor behavior,
metadata compatibility/preservation observers and linked resource measurements.
General in-place common-Root reconstruction, Kernel/Root image replacement,
physical power-loss certification, cross-dataset/device moves, encryption,
snapshots/backups/scrubbing, production filesystem scale and external formats
remain separate. Independent cold recovery of the supported cohort is required
by M8; app-update rollback alone cannot qualify this storage base.

The exact format and adapter contract are in
[WORKSPACE_STORAGE](../designs/WORKSPACE_STORAGE.md). Review on increasing
capacity/concurrency, changing format, introducing migration, adding durable
client history, compaction/redundancy, or widening authority.
