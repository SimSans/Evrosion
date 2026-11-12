# Explicit desktop storage profile

This source/model slice separates the full desktop's three Store-v2 regions on
one disk. It preserves all prior actor profiles, the block-v1 codec, legacy
`StoreRegion::new` mapping and durable format2. No integrated VM, physical
isolation, input/picker, whole-desktop or power-loss acceptance follows here.
Current milestone truth remains in [project status](../../docs/status/PROJECT_STATUS.md).

| Owner/region | Client logical sectors | Actual physical sectors |
| --- | --- | --- |
| Root System |0..13|16..29|
| File Notes (FileA) |0..13|32..45|
| File Private (FileB) |16..29|48..61|

The File client refuses14/15 and>=30. System refuses>=14. Sectors30/31 and46/47
are guards; existing seed/control sectors0/1/2 are not accessible through either
desktop slice. `ev_store::desktop::Client` performs translation only in the
userspace Block actor. The actual retained receive endpoint chooses client and
window before buffer/device effects. The packet does not select a client.
Replies retain the original logical sector. Global ATA flush may persist prior
writes from either client; no cross-region atomic transaction is claimed.

Root health uses `StoreRegion::for_profile(...,Profile::Desktop(Region::System))`,
with a real System endpoint/window. This sends logical0 rather than legacy
physical16. The legacy constructor deliberately still sends physical16. Typed
System routing prevents health writes from addressing either File region. The
trusted Root controller separately retains management capabilities; this is not
a claim that owner control lacks the power to deliberately access its files.

## Actual startup roles and windows

`ev-block-service` feature `desktop-driver`:

| Role | Authority | Driver virtual leaf |
| --- | --- | --- |
|1|ATA IoPorts READ + WRITE (3)|scoped private ISA controller|
|2|System Memory READ + WRITE + MAP (7)|508|
|3|System Endpoint RECEIVE + CONTROL (272)|no pointer|
|4|File Memory READ + WRITE + MAP (7)|507|
|5|File Endpoint RECEIVE + CONTROL (272)|no pointer|
|6|Root events Endpoint SEND8|no pointer|

`ev-file-service` features `desktop` (open existing) or `desktop-provision`
(explicit blank-only provisioning), with legacy server/app unchanged:

| Role | Authority | File virtual leaf |
| --- | --- | --- |
|1|File backend Memory7|508|
|2|File backend Endpoint SEND8|no pointer|
|3|App request/response Memory7|507|
|4/5|Notes RO/RW Endpoint RECEIVE + CONTROL (272)|no pointer|
|6/7|Private RO/RW Endpoint RECEIVE + CONTROL (272)|no pointer|
|8|Root events Endpoint SEND8|no pointer|

The desktop admission profile consumes the one shared
`root_v2::catalogue::CHILD_LIMITS` constant (currently16,384 CPU ticks,
32 frames, one process and one thread). Desktop Block and File startup reject
other declared limits. This finite interactive profile is distinct from the
unchanged2,048-tick historical storage fixtures. The controller stop remains
separate from CPU accounting; outgoing shared-buffer RPCs use checked
stop+512 deadlines, and inherited nested deadlines never extend that value.

The runtime must prove the two actual Block Memory objects are distinct, each
has exactly its intended mappings/owners, and no second reader/writer can reuse
a live window. Distinct bootstrap integers alone do not prove object identity.
One ATA actor serializes both clients. `DesktopFiles::regions(&mut self)` gives
the one File backend/window exactly two non-Clone disjoint region tokens. Its
shared RefCell detects reentrancy without unchecked aliases; poison after any
ambiguous reply/transport failure covers BOTH regions. Each Store remains the
exclusive owner of its own physical region. A second writer or old unquiesced
service is forbidden even if it has a different Rust backend value.

The runtime admits no timeout/cancellation-driven shared-window reuse before
the declared controller stop. `DesktopEndpoint` retries ONLY canonical status2
Busy rejected before CallId/escrow/wait/window/device effects. It preserves the
same absolute request deadline and bytes, retains the window, checks monotonic
clock/stop, and has a finite4096-attempt budget. It never retries accepted
timeout, death, malformed or ambiguous errors. The old Endpoint behavior is
unchanged. File forwards the actual inherited RPC deadline29 to nested Block;
neither actor extends it.

Block initializes ATA, self-binds both actual receivers21, then emits
`EVBLRDY1`. File opens/provisions both objects, self-binds all four receivers,
then emits `EVFLRDY1`. Canonical Full event replies retry under the finite stop.
Readiness advertisements do not grant authority or replace actual admission.

## Provisioning, logical files and metadata

There is no desktop read of fixture control-sector2. `desktop` only opens existing
volumes and refuses unformatted/corrupt data. `desktop-provision` preflights BOTH
regions blank before any format, then uses unchanged `Store::format_new`.
It never reformats an existing region on open/envelope failure. A failure between
the two independent formats can leave a partial fresh setup; recovery must
preserve the completed volume and use an explicit owner/provisioning path for
the remaining blank region. This profile does not claim atomic two-volume setup.

The exact seed bytes live in `ev_file::desktop::{SEED_NOTES,SEED_PRIVATE}` and are
part of the actual measured File image. Each volume has its own internal Store
Object1, durable operation high-water and EVFILE01 receipt. Desktop logical
identity is (this owned volume, Notes1/Private2); it is not a raw sector or global
operation ID. Endpoint binding chooses object and RO/RW. The app-facing generated
File-v1 frame remains unchanged and contains no object/volume/sector selector.
Data-container generation fields remain explicitly unresolved/unadmitted with
no known-good claim; only the System region participates in real boot health.

Scalar `MetadataQuery` on NotesRO4 or PrivateRO6 is `FMQ1`, one field byte
(0counter,1..4 SHA-256 payload word0..3), then three zero bytes. It never touches
the App shared window. Every word comes from an actual private Store read and
envelope validation; hashes establish integrity, not authentication. Root reads
counter-before/four digest words/counter-after and refuses a change. The bounded
picker profile keeps RW authority in serialized Root and delegates none to App
or another writer while taking this snapshot. This is not a general multiwriter
atomic read or a capability minted from a digest.

Valid query replies are the full raw u64LE under the actual protected call/reply
lease. A valid backend query failure terminates File instead of fabricating a
word. Malformed queries/wrong RW route receive `FME1`+reason1/2. A valid digest
word must never be classified by its bytes as an error tag. Unknown scalar
operations/reserved fields reject before App buffer or Store access. Normal
File calls still use the exact `file_test::CALL/REPLY` scalars and private256-byte
request snapshot; RO Replace denies before backend reads.

## Integration proof still required

- Admit/measure both File profiles and the Block image with actual frame/stack
  accounting; do not silently grow stacks or assume the old File stack bound.
- Execute both Block clients/windows and File endpoint bindings in one real VM;
  prove wrong-client/guard/System-to-File denial before window/device effects.
- Root health/failure/rollback must preserve the complete FileA/FileB regions.
- Provision seeds through the real File owner, replace/replay each separately,
  stop old writers, cold reopen both, and independently inspect envelopes,
  counters, receipts, guards and mutation-free metadata reads.
- Actual selected App grants must bind exact active File RO object/role and
  current metadata, not merely Endpoint kind. Prove Notes cannot become Private,
  RW/backend authority or an unrelated/recycled process through a packet ID.
- Repeat per-region interruption/recovery and actual grant/revocation/teardown
  with retained evidence. Existing portable models and historical independent
  M3 physical proofs cannot be relabelled as this full-graph physical proof.
