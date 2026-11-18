# Bounded workspace storage format and adapter contract

Status: portable implementation; target integration/qualification pending.
See [ADR-0104](../adr/ADR-0104-bounded-workspace-dataset-and-durable-namespace.md).

The selected V5 Block may additionally negotiate the fixed-sector private-RAM
PIO mechanism in [ADR-0116](../adr/ADR-0116-selected-fixed-sector-pio.md). Its
`pio-words256` feature preserves this format, physical extent, operation counts
and original deadlines. Compilation/model tests do not qualify native save
latency, timer delivery, failure fallback or independent cold recovery.

## Owned region and compatibility

The backend takes relative sectors of an exclusively owned new region. The
Block endpoint must fix that region and refuse overflow before buffer/device
effects. Required extent is152322 sectors of512 bytes:77988864 bytes. Physical
base assignment is an integration decision; these relative addresses grant no
access. All existing Store-v2/File-v1 regions and actual volume/object IDs stay
unchanged. No migration operation exists in this package. Unknown, nonblank,
corrupt and partially provisioned regions are never reset to make open succeed.

| Relative sectors | Meaning |
|---|---|
|0–1| Two mirrored/alternating committed roots; NEW-only provisioning markers before roots exist |
|2–129| Catalog bank0,128 sectors |
|130–257| Catalog bank1,128 sectors |
|258–152321|16896 allocation units, nine sectors each |

16384 units provide64MiB of committed4KiB-rounded allocation.512 units are a
separate2MiB staging reserve. One unit has a512-byte integrity header followed
by eight512-byte payload sectors. File size is at most1MiB/256 units. A zero
length file has zero units and SHA256(empty). Full capacity includes trash;
replacing an existing1MiB file can stage its full new bytes while quota is full.
The contiguous allocator may refuse fragmentation honestly; it cannot erase
retention roots or silently compact live data. Production pooling is future.

## Canonical disk records

All integers are little endian; reserved and unused bytes are zero. SHA256 is
integrity checking, not publisher authentication or capability validation.
Decoders re-encode records to require exact canonical bytes.

Root512 uses magic `EVWROT01` and format1. It contains nonzero16-byte DatasetId,
sequence, namespace revision, current catalog bank/digest, last global operation
and fingerprint, typed receipt, and optional stage. The final32 bytes hash the
preceding480. Sequence is exactly last global operation+1 and does not wrap.
Two valid equal-sequence roots must be identical; valid different dataset IDs
refuse. An unsupported workspace root version refuses without writes. Highest
valid sequence is selected; a valid selected root with damaged referenced data
fails closed rather than falling back to an older user document. Root mirroring
before ACK protects the same acknowledged state against one later bad root.
After interruption, read-only open can expose one valid selected root and flag
`needs_mirror_recovery`. Fresh operations are fenced. Explicit recovery writes
the invalid/outdated peer first, flushes/readbacks, then mirrors the original;
it never tears the only good root as its first write. Original exact-operation
retry finishes this mirror before returning an acknowledged replay.

Catalog entries are256 bytes, two per sector. `EVWENT01`/format1 binds slot,
generation, kind, trash bit, parent slot/generation, content revision, byte
length, allocation extent, data stamp, full-file digest and up to96 UTF-8 name
bytes. SHA256 covers the first224 bytes. The root also hashes the complete64KiB
bank. Vacant slots retain only generation. Root is implicit `{slot:0,gen:1}`;
dynamic slots1–256 increment generation on reuse. Dynamic directories number
at most32; object paths are at most eight levels below root. Cycles, dangling
parents, duplicate visible siblings, out-of-range/overlapping extents, quota
overflow, invalid names and stale identities refuse on open.

Names are exact UTF-8 bytes, without normalization/case folding. Empty names,
slash/backslash, controls, dot/dot-dot and names over96 bytes refuse. Root alone
has empty display name and parent=self. Namespace mutations require the exact
current namespace revision. File content commit also advances that revision;
staging checkpoint/abort does not. Rename/move retain stable object generation
and content revision. Removal retains the original parent/name for restore;
restoring a collision refuses rather than renaming or replacing implicitly.

Chunk header512 uses `EVWCHK01`/format1, exact object generation, stage data
stamp, chunk index, valid length and SHA256 of the entire zero-padded4096-byte
payload. Its final32 bytes hash the preceding480. Reads verify header, payload
digest and zero tail before copying bytes. Full-file commit/explicit scrub additionally
verify SHA256 over exact content length. Valid checksums do not authenticate
disk ownership, and damaged data without another good copy cannot be repaired.

## API and ownership

`Dataset<D: ev_store::SectorIo>` borrows a caller-owned resident `Scratch` and
owns its one backend. Construct Scratch once in target resident storage; its
const initializer is not a recommendation to allocate a catalog on a process
stack. No open/format operation returns a catalog/document-sized value.

| API | Result/meaning |
|---|---|
|`format_new(device,&mut scratch,DatasetId,deadline)`| Read-preflight the complete region; format only if entirely blank |
|`Provisioning::new`/`scan_step`/`finish`/`resume`| Bounded preflight continuation and explicit NEW-only recovery before normal desktop admission |
|`open(device,&mut scratch,deadline)`|130-read metadata/graph validation; retains recorded staging progress; no hidden full-content scrub |
|`needs_mirror_recovery`/`recover_metadata`| Read-only discovery vs explicit owner completion of an interrupted root mirror |
|`dataset_id`, `namespace_revision`, `metadata`, `name`, `list`| Actual stored identity/state; one entry per enumeration call |
|`create`, `rename`, `move_object`, `trash`, `restore`, `restore_at`| Transactional namespace operations requiring expected namespace revision |
|`begin_write`| Expected content revision, declared length and exact final SHA256; one stage at a time |
|`write_chunk`| Sequential offset;4096 bytes except final shorter chunk; confirms durable verified progress |
|`pending_stage`| Exact stage/object/expected revision/length/written/digest for trusted reconciliation |
|`commit`| Verify complete bytes/digest and publish content revision+1 |
|`begin_verification`/`verify_step`/`commit_verified`| Private bounded RAM continuation for full hash verification before final catalog publication |
|`scrub_file`/`verify_staged_chunk`| Explicit full-file scrub or one checkpoint verification; no implicit startup scan |
|`abort`| Explicitly abandon one safely serialized stage; committed content unchanged |
|`purge`| Permanently remove a trashed file/empty directory under exact ReclaimFence |
|`read`| Bounded caller buffer<=4096; expected content revision; verified range bytes |
|`next_operation`, `last_receipt`| Trusted owner allocation/reconciliation; no raw client global-ID selector |

`restore` retains its original-parent/name behavior. `restore_at` publishes one
atomic Restored transaction to an explicit live destination and validated name,
binding destination/name in its distinct durable request fingerprint. It checks
collision, cycle and depth constraints for the complete subtree before writing.
This avoids an intermediate visible restore followed by a separate move and
matches the generated Workspace Restore request's single expected namespace
revision. Hidden descendants move with their stable parent/object identities.

Object IDs/metadata and `include_trashed` flags supply no authority. Authenticated
service endpoint/caller binding fixes dataset/object and permitted methods.
Listing a directory grants neither read nor edit of its children. Trash hides
the namespace subtree; an existing exact-object reader can continue reading
retained bytes until the trusted owner revokes it. Writes to hidden objects
refuse. Purge and later slot reuse cannot redirect an old generation.

`ReclaimFence` names exact object, current namespace revision and nonzero local
authority epoch. Before supplying it, the actual owner must stop/revoke affected
grants/readers, fence new delegation for the operation, and prove device/window
quiescence where relevant. It is not itself a kernel capability or evidence.
Subtree purge is bottom-up, one individually fenced object at a time; a nonempty
directory is never silently reclaimed. Aborted staging becomes reusable only
under the same single-writer/quiescence requirements as every operation.

## Wire mapping, receipts and uncertainty

Use the generated `ev.internal.workspace@1`/`ev.internal.file@2` contracts under
ADR-0105. Control metadata stays256 bytes; data uses a separate prebound borrowed
Memory Object window<=4096. No app selects relative/physical sectors, dataset
mapping, backend global operation or another object's service route.

Wire operation IDs are client-session nonces. Derive ClientRequest's16-byte
caller/incarnation identity and lease epoch from actual authenticated transport,
then add its client nonce. Allocate a separate global OperationId through the
serialized backend owner and attach the scope with `for_request`. Maintain the
mapping and exact payload for the lifetime of an unresolved request. Two
clients' nonce1 values are distinct. Caller bytes/epochs copied from app packet
fields do not authenticate that scope.

The LAST root receipt retains global ID, bound ClientRequest, full method/args/
content fingerprint, result kind, object/revision, namespace revision, stage,
confirmed bytes and root sequence. Exact current retry returns that receipt
without I/O when root mirrors already match; an interrupted mirror finishes
before replay ACK. Changed caller/lease/nonce or changed request conflicts. Reusing the
same immediate client request with a fresh global ID is refused. Old global
IDs are stale after another transaction, not proof of nonexecution. There is
no unlimited replay table. An adapter must preserve unresolved mappings or
report Stale/Uncertain and keep ownership fenced; never auto fresh-ID replay.

Commit wire length/digest must match `pending_stage` before invoking commit;
its response must match the backend receipt and verified current metadata.
Client transfer IDs map to trusted stage IDs separately; they are not backend
operation selectors. An accepted I/O error poisons subsequent access, including
receipt/stage queries. A typed error never proves a write did not execute.
Close the old owner only after real peer/device/window retirement, cold-open,
reconcile the original operation and publish success only from durable truth.
Returning a Rust backend value alone establishes none of that quiescence.

Reads can verify/copy one chunk before an error on a second; callers must discard
the entire output on Err. Outgoing buffers/loans stay fenced until actual
completion or established quiescence. Cancellation cannot free shared memory
or staging merely because a boolean or timeout changed.

## Publication, recovery and proof boundaries

Catalog publication: write inactive bank → flush → readback hash → alternate
root → flush → exact readback → mirrored same root → flush → exact readback →
receipt. Data publication: durably reserve stage → chunk payload → flush →
header → flush → verified readback → durable root offset. Final commit verifies
all chunks/full hash before changing the catalog; staged bytes never masquerade
as committed content. Every metadata/root step uses the existing absolute
SectorIo deadline. This package neither renews deadlines nor certifies that a
concrete driver honored them.

Cold open verifies roots, canonical catalog, graph and all extent/identity/quota
references using130 reads only. Each delivered chunk verifies its own identity
and bytes; full commit/scrub verifies the aggregate hash. `verify_staged_chunk`
lets recovery verify retained checkpoints incrementally before presenting them
as newly checked progress. Metadata progress alone does not assert those bytes
were freshly reverified. Unacknowledged trailing stage data can be overwritten
by the SAME offset/intent after recovery. A stale request cannot choose another
operation or make unresolved bytes disappear.

`CommitVerifier` retains an opaque SHA256 continuation tied to exact DatasetId
and stage. `verify_step(max_chunks,deadline)` checks bounded immutable chunks
and complete digest without consuming a global operation. `commit_verified`
publishes only that still-current complete proof; an aborted/replaced stage
invalidates it. Allocate the trusted global publication ID when ready, while
retaining the actual client's original nonce/intent. The synchronous `commit`
helper drives the same verifier under one captured deadline; it is not license
to renew an admitted RPC. A target service must use continuations or a separately
measured suitable finite operation budget and honest pending/uncertain replies.

## Provisioning progress, resume and actual I/O costs

The NEW-region scan reads152322 sectors. It cannot be hidden inside an8192tick
metadata/startup health window. Run a guest provisioning owner before ordinary
desktop/cohort health and keep the existing protected recovery path available.
`Provisioning::scan_step(max_sectors,deadline)` captures a bounded batch; its
caller returns to scheduling/progress/input between calls. Each batch has its
own deadline, not an extension of an accepted RPC. Scanning is RAM progress
until a marker commits; loss before a valid marker can require scanning again.

Only after the full region is blank does finish publish two canonical
`EVWPRV01`/format1 markers with exact DatasetId, profile extents and checksum.
Then it builds empty catalog/roots. Without a committed root, normal open
returns ProvisioningRequired if a valid marker exists. Explicit
`Provisioning::resume(expectedDatasetId)` refuses existing committed roots,
legacy/unidentified data and mismatched IDs, rechecks the untouched data area in
bounded steps, and rewrites only this known-empty dataset's metadata. If a valid
committed root exists, use open plus mirror recovery instead. A torn first
marker with no valid copy remains Corrupt/nonblank, preserved for explicit owner
action on that new region; it is never automatically erased or assumed empty.

`finish` is269 I/O calls including the initial markers,263 after an existing
marker. It needs a separately measured finite provisioning budget. The
synchronous `format_new` helper drives the same scan/finalization under one
deadline for portable callers; passing a long host-model deadline does not
qualify a guest driver, health contract or real provisioning UX.

Observed portable SectorIo counts (reads,writes,flushes), with exact assertions
in the focused tests:

| Operation | Read | Write | Flush |
|---|---:|---:|---:|
| Complete NEW format, including blank scan and markers |152454|132|5|
| Metadata/graph open, any data occupancy |130|0|0|
| Create or comparable catalog mutation |130|130|3|
| Begin stage |2|2|2|
| One full4KiB stage chunk/checkpoint |11|11|4|
| Complete1MiB Save (begin,256 chunks,verify,commit) |5252|2948|1029|
| One verified data chunk / one verifier step |9|0|0|
| Explicit1MiB full-content scrub |2304|0|0|
| Root mirror recovery |2|2|2|

These are actual portable calls, not elapsed/IRQ ticks or target latency. The
1MiB verifier can yield after nine-read steps; final catalog publication still
has130 reads/130 writes/three flushes and needs measured service admission.
No normal Ready/Known Good signal can substitute for that measurement. Cold
independent observers call open/read/scrub only, never provisioning or recovery
writes. Core Scratch measures53760 bytes and Dataset344 bytes on the host;
linked target placement/stack/resource checks remain separate. The private
CommitVerifier measures224 host bytes. These layouts are host observations;
Dataset's concrete backend and target linked layout still require measurement.

The current focused qualification is14 passing host tests,5016 mutation/staging
cuts,72 interrupted mirror-recovery cuts and108 NEW-provisioning cuts.72 of the
provisioning cuts resume explicitly; one torn first marker remains unidentified
and preserved for owner action. Strict host all-target lint and bare
`x86_64-unknown-none` release typechecking pass. A bare generic library check is
not a linked driver/service stack census or VM execution. Command receipts,
source hashes and the retained earlier failures are in
[the scoped qualification record](../../libs/workspace-store/QUALIFICATION.json).

Host tests exercise real memory-sector bytes and volatile-cache/write-through
models with read/write/flush errors, torn writes, cold owners, full64MiB quota,
1MiB staging, scoped nonce collision, all profile bounds, corruption, refusal,
trash/restore/reclaim and stale generation reuse. Their retained command logs
are separate from target execution. They do not prove actual grant revocation,
shared-loan retirement, ATA reset, File/Block restart, independent common-Root
recovery, physical power loss or a complete M8 acceptance. Those remain required
integration evidence under the plan; existing app-update rollback is insufficient.
