# Internal M8 RootV5 graph, admission metadata and layout

Status: contract/model implemented; actual V5 Kernel factory, source backing,
actors, optimized linked census and VM qualification pending. These records
must not be reported as executed M8 acceptance.

The selected Level B resource mechanism is recorded in ADR-0109. New code lives
under `libs/userspace-contract/src/root_v5/`; V1–V4 bytes, public parser limits,
source schemas and generated bindings remain independent. There is no validated
V4 base/catalogue wrapper inside V5 and no cast from an old admission token.

## Independent bootstrap and manifest

Root uses `EVROOT05`, version/profile5, header144, max40 canonical24-byte grants
and fixed1104 bytes. `FullGraph` accepts exactly37 named sources, exact kinds/
rights, sorted selectors, distinct handles, finite limits and zero reserved/tail
bytes. An artifact hash, scalar ID, parsed source name or Context does not create
a capability. Actual source custody must join full generation/lineage, matching
backing, expected rights and the independently measured Root image/catalogue.

The manifest uses `EVBM0005`,208-byte header plus37*32-byte grants. It binds the
new Root ABI, startup1104/profile5, exact sources, Root limits and full three-page
catalogue digest. Authority hashing uses the separate domain
`evrosion.bootstrap.authority.root.v5\0`. Kernel selects the V5 factory only after
that independently verified manifest; default/old factories stay strict.

There are ten source images and eleven independently admitted children. Editor1
and Editor2 intentionally share one immutable Editor image and local role shape.
They have separate logical instance IDs2/3, Jobs, full process/thread/incarnation,
surfaces, two-page operation windows, controls and selected-grant inboxes. Binding
measurement is per instance; identical Editor instance-binding digests refuse.
Sharing executable bytes never shares another instance's authority or state.

The new528-byte `EVSRVC05` child record supports at most16 grants for Workspace16
and Display10. `child::Profile::parse(Child,bytes)` checks exact per-child limits,
count and local selector/kind/rights triples. Every other actor retains the336-
byte/max8 v1 bootstrap and ABI, including new Editor6 and Block8. Catalogue rows
bind each image's exact format, ABI, limits, layout, maximum private resources
and stack. The ordinary v1 parser is not widened to accept the new record.

## Closed child graph and authoritative routes

| Child | Startup roles | Job template | Startup bytes |
|---|---:|---:|---:|
| Shell |4|2|336|
| Input |3|0|336|
| Workspace (namespace + File)|16|2|528|
| Block|8|0|336|
| Display|10|2|528|
| NetDriver|4|0|336|
| NetService|5|1|336|
| Files|7|2|336|
| Editor1|6|3|336|
| Editor2|6|3|336|
| Inspector|6|2|336|

The23 closed channels contain14 RPC routes, five asynchronous controls and four
separate selected-grant inboxes. RootEvents is a separately created bootstrap
source at reserved wire23; it is not a Channel or an ordinary sender identity.
The preexisting16-route RPC bound therefore remains sufficient for this graph.

DisplayPresent is shared by Root, Shell and the four applications. Display must
select its actual producer from Kernel-captured serving origin and Root-only
owner registration, never a surface index or claimed PID in the body. Display
local role10 is DisplayControl RECEIVE|CONTROL; **only Root owns SEND** on that
separate endpoint. No ordinary child receives SEND/DERIVE/TRANSFER to it. Root
registers exact admitted producer process/thread/incarnation, logical source ID,
mapping epoch and the Kernel-admitted source-role mapping. No first-caller rule,
packet Root marker or public PID lookup authenticates this registration.

Workspace local role10 is Files' namespace receiver. Its separate role16 is the
RootWorkspaceControl receiver at wire22; only Root has SEND. The shared-data
control window is fixed by that route, not a body address. Per-client File2
lease receivers11–14 bind exact current caller, object/revision and rights.
Root binds/revokes them only through role16. Ordinary File2 bodies cannot create
bindings. App SEND handles are delivered through their own selected inboxes;
there is no startup File lease or global storage capability in an Editor.

Rebinding a lease endpoint requires the old derivation revoked and all accepted
calls/windows settled or independently quiescent. A saved scalar endpoint number
must never retarget an old grant to a different object. Source generations,
original deadlines and exact requester identity remain mandatory.

Root receives actual asynchronous sender identity through existing event39.
For shared RPC, the additive ServingOrigin57/INFO58 descriptor
`0x0000000100080001` is required. Its endpoint+serving-nonce query resolves the
actual immediate caller and retained call; live status and exact current
recipient/endpoint are checked before any shared-window access. Receive34 bytes
remain unchanged. Metadata has no substitute for that actual captured context.

## Resource envelopes and exact census boundary

The selected M8 Authority storage is96 objects,512 lineage nodes,64 Spaces and
96-slot trusted Workspace control domains. Ordinary domains stay16. Old
`Authority::new()` retains effective64 objects/256 nodes/40 Spaces; existing
control factories retain64 slots. The selected trusted constructor/factory is
available only under the new workspace feature. Default compiled arrays remain
unchanged. Wider physical storage is not permission, and existing domains are
never upgraded in place.

| Declared M8 count | Meaning |
|---|---|
|82 objects|37 sources +23 endpoint objects +22 child Job/Process objects; lower bound before remaining actual factory/lifecycle ownership|
|86 objects|Prior lower bound +two dynamic image objects +one held Job/Process pair; still not a measured maximum|
|49 Spaces|Three Root domains +22 child domains +23 mailbox escrows +RootEvents escrow|
|51 /52 Spaces|One held replacement / plus one retained channel replacement escrow|
|306 lineage nodes|111 Root source levels +23 endpoint roots +22 Job/Process roots +150 child derivations|
|340 lineage nodes|Prior lower bound plus largest16-role held replacement's32 derivations and Job/Process pair|
|71 Root handles|37 sources +23 channels +11 ProcessCONTROL after setup-only JobCONTROL closure|
|76 Root handles|Prior count +two dynamic images +held Job/Process +one grant scratch handle|
|13 Jobs /12 processes /12 threads|Boot is one Job, with no userspace Boot process; Root plus eleven children|
|14 /13 /13|One held replacement; Scheduler/Registry16-row process/Job bounds remain separate|

These numbers are **derived proposed lower bounds**, not reservations, actual
maxima, linked analysis or PASS. Canonical census status remains0/proposed. The
actual complete source-bound census must account for retained stopped rows,
temporary handles, lineage ancestors, dynamic images, queued grants, receiver
replacement, rejected attempts and every boot/recovery phase before activation.

Closing setup-only JobCONTROL after actual Start and negotiated ProcessJobInfo55
descriptor `0x0000000100090003` releases a local handle. It does not free the Job,
accounting or ancestor lineage. Root keeps ProcessCONTROL; query55 may read the
retained stopped association only before actual Registry retirement. Held and
retired associations refuse. It must never fall back to JOB_INFO42 cap0, which
selects Root's own Job. Registry retains ownership until actual lifecycle reaping.

The four fixed `[CPU,frames,processes,threads]` templates are:

| Template | Exact limits | Actors |
|---|---|---|
|0|1000000,32,1,1|Input/Block/NetDriver; unchanged limits|
|1|1000000,64,1,1|NetService; unchanged limits|
|2|1000000,128,1,1|New UI, Workspace and Display|
|3|1000000,512,1,1|Each independent Editor|

Root limits are4000000/4096/13/13; the Boot parent is8000000/8192/14/14.
CreatorJob is the actual RootJob, so all children and shared/package backings
are charged in this4096-frame descendant subtree. This ceiling is distinct
from the unchanged240-image/244-private/246-base Root ELF loader envelope.
Existing sampled CPU policy64/256 per child and256/256 Root/parent stays explicit;
renewal never resets cumulative usage. Template IDs are not scalar quota values:
the selected Registry resolves their fixed limits and checks the exact measured
image. Shared RAM is charged once upstream, not once per mapping. New Editor
buffer capacity does not widen any old Input, Block, Net or v1 image envelope.

## Image and mapping layout

All private images stay in the512-page/2MiB user window. UI and Workspace image
targets are96 pages/private100/loader102; Display80/private84/loader**88** includes
two extra RAM page-table frames for its separate MMIO aperture. Editor384/
private388/loader390 provides room for one resident1MiB document, code and stack.
The actual ELF and stack must still fit; neither target nor quota establishes it.
Legacy-core image64 behavior remains unchanged, including its smaller exact Job
quota, so unused maximum syntax never reserves extra frames.

New UI/Workspace/Editor/Display stack is480–487 with absent guards479/488. The
Editor document region64–319 does not intersect its source surface384–446,
two-page File window506–507, bootstrap509 or entry stack511. Legacy Core keeps
its original256–259 stack and guards255/260. Root keeps stack256–263 and its
240-image-page limit. Actual linker, descriptor and loader must agree.

| Actor/source | Page range |
|---|---|
| Root PackageB /PackageA |304–366 /384–446; old immutable package maxima preserved|
| Root protected source |448–498; guards447/499;51 pages|
| Root readonly catalogue |500–502; exactly12288 bytes|
| Root Workspace control/bulk |503–504;2 pages|
| Root Net client /NIC |505 /508|
| Workspace Root control |494–495|
| Workspace Files /Editor1 /Editor2 /Inspector windows |496–497 /498–499 /500–501 /502–503|
| Workspace new Block I/O /legacy File I/O |506 /508|
| Block System /legacy File /Workspace I/O |508 /507 /506; exact first six roles retained, new roles7–8|
| Display Files /Editor1 /Editor2 /Inspector /Shell sources |64–126 /128–190 /192–254 /256–318 /320–382|
| Display protected source |384–434; guard435|

The reference is640x480 logical pixels. Default App content320x180, with at most
320x200/63-page backing, supports a bounded two-by-two window reference below
the reserved640x80 Root plane. Shell can provide a bounded panel from its own
63-page capacity; it does not need a full640x480 bitmap. Root protected pixels
use51 pages and a512-byte control/header prefix; normal V5 surfaces use256.
All producer rasters are typed variable-geometry `EVSURF05`, independently of
legacy fixed320x200 `EVSURF01`, whose parser is not loosened.

Surface header owner, instance, logical source ID, mapping epoch, frame/view/model
revisions and extent are descriptive values. Root-only Display registration plus
actual ServingOrigin and Kernel-held mappings authenticate their meaning. A
packet changing Producer to ProtectedRoot cannot acquire that source or draw
over it. Apps learn actual self identity through a separately negotiated M8
query when required; no old ProcessIdentity38 ABI or ambient PID authority changes.

The separate `services/workspace-display` actor uses an incremental native
adapter: only the currently blocked producer is sampled after actual57/58
origin resolution. A Root-only `display_control` transaction installs geometry,
registration and the full64-bit model revision. Commit neutralizes ordinary
pixels, redraws trusted chrome and returns a repaint mask; Root obtains fresh
producer Presents for the new scene. It cannot gather immutable borrows from
other live producers or promise a full-scene atomic bitmap. Ordinary clear,
chrome and copies exclude the reserved Root plane. Only the independently
registered Root producer paints that plane. Native protected input and owner
confirmation remain fenced until current Root presentation; semantic delivery
and trusted attention require their own actual adapter evidence.

## Catalogue and lifecycle preservation

The independent12288-byte `EVCOH005` catalogue records ten measured images,
eleven instance bindings, separately packaged Files/Editor/Inspector plus the
Editor candidate, explicit network/device/timer policy and exact graph/layout/
census/dynamic policy records. Editor candidate keeps the same stable App ID;
the three application identities differ. Current and candidate package/image
digests differ. No embedded old catalogue is relabeled as V5 acceptance.

Each original128-byte package record retains its exact identity/hash/bytecount
fields. A separate four-entry16-byte placement table follows the dynamic record:
kind u16, bank u8, version1 u8, offset u32 and duplicate exact bytecount u64.
Current bank0 is Role19/page384; candidate bank1 is Role20/page304. Files,
current Editor and Inspector use bank0; candidate Editor uses bank1. Offsets are
measured producer inputs aligned to16 bytes. Checked extents must fit the
independent63-page bank and may not overlap another package in that bank. This
table does not infer package bytes or authority: Kernel admission must compare
the actual complete package bytes/hash/length at that exact physical location.
The previous package records/section offsets and catalogue12288-byte bound stay
unchanged. Missing, malformed, overlapping or conflicting placements refuse.

Immutable package bytes, independently stored legacy File-v1/Store-v2 data,
private-note data, dynamic workspace data, update metadata and recovery state
remain separate. Network and Root-only RTC policy keep their declared PIO/range,
time and trust limits. A network-policy record does not supply entropy, UTC,
TLS trust, DMA absence, signing or accepted health. Actual signed application
update, later durable workspace edits and independent offline recovery must be
qualified together. New384-page dynamic admission is selected M8 metadata, not
a silent widening of the old PD1/IMAGE_CONTROL52 path.

The additive `root_v5::dynamic` contract negotiates actual IMAGE_CONTROL52
Initialize result2 and requires the separate strict256-byte `EVDYN002` header.
It preserves the fixed PD1 geometry and two64-page package owners, charged to
the selected Root/Boot subtree. The mechanism's262144-byte owner bound differs
from a catalogue package bank's258048-byte bound. Its distinct descriptor
transcript binds the selected Editor factory's exact13 policy values,
RootV5/child ABI, finite1M/512/1/1 limits and six role triples. Kernel does not
select this factory from a signed AppId; Root still verifies package/signature,
actual program labels and persistence policy. This does not widen oldV4 code.
PrepareProcess9 accepts only an actual held ProcessCONTROL after six exact
delegations, allocates/readbacks private ELF/bootstrap while Held, and maps no
old shared Surface/FileFrame. Actual Start requires old process retirement and
exact shared scrub. These contract records are not proof that native dynamic
admission, replacement, update or recovery has passed.

The existing `EVMDYN05` catalogue tail `[1,2,1]` describes Root-only issuance,
two retained package owners and one held candidate. It is not an opcode/header
version selector. Actual Initialize2 must be negotiated; the Root42b2 catalogue
bytes remain unchanged by this additive mechanism contract.

`verify.py` independently checks the Root/child ABI and dynamic2-description hashes and, with
the retained baseline source, all22 RootV2/V3/V4 source/layout/fixture bytes.
Host tests cover syntax, hostile metadata, exact role distribution, sender
boundaries, editor separation, canonical resources, guard ranges and new surface
headers. They do not prove actual admission, shared-memory quiescence, graphics,
storage, update recovery, ownership delivery or a usable native desktop.

The first actual11-child graph observed57,887 aggregate charged CPU at58,000
elapsed guest ticks. The earlier65,536 Root cumulative ceiling therefore cannot
cover the required30-minute session. Selected M8 finite CPU ceilings are4M Root,
8M Boot and1M per-child template, preserving all period/quota controls and
accumulated usage. Every affected selected parser/descriptor/artifact must be
rebuilt; older profile CPU limits remain exact. This change is admission policy,
not a completed30-minute session or a counter reset.
