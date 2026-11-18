# Internal session-network Root profile4

These safe codecs describe a new bounded profile. Parsed metadata creates no
capability, physical mapping, accepted-work retirement, successful device run,
entropy approval, time trust or network grant. Existing ServiceImage/v1,
Desktop/v2 and Native3 formats remain separate and unchanged.

`root_v4::Bootstrap` syntax uses magic `EVROOT04`, version/profile4,912bytes,
header144 and32 slots of24bytes. `FullGraph` requires exactly29 named sources.
Selectors1..22 preserve Native3 triples. New selectors23/24 are NetDriver and
NetService image MemoryREAD1;25 is NicPorts kind7/rights227;26/27 are the two
distinct network shared windows kind1/rights231. Selector28 NoteWindow is also
kind1/rights231 so Root can derive the exact App role7 MemoryRW|MAP7 through
the existing grant path. App receives no branch/delegation rights. Raw spare
slots do not expand FullGraph. Selector29 RtcPorts is kind7/rights3 (READ|WRITE),
Root only, with no DERIVE/TRANSFER/control grant or child use. Its immutable
byte ranges permit only index70 writes and data71 reads; RTC data/clock writes
are refused independently of the capability read/write bits.
Ordering, alias handles, bounded limits and all reserved bytes are checked.

The v4 manifest is1136bytes:208header +29*32 grants. It uses `EVBM0004`, the
v4 ABI at48..80, startup/version4/912/profile4 at168..174 and the full4096-byte
catalogue digest at176..208. Actual producer/Kernel/Custodian integration must
explicitly accept this profile; no v3 validated object is a v4 admission token.
`ABI` is SHA256 of the exact `ABI_DESCRIPTION` bytes. Factories must independently
verify loaded images/descriptors, actual sources and content/layout measurement.

`graph` preserves the first six children and wire indices0..14. NetDriver is
child6, NetService7. RootEvents remains reserved wire15; new RPC routes use16
and17, making18 actual wire slots for17 declared child routes plus RootEvents.
`Channel::wire_index` deliberately is not a dense array index into `CHANNELS`.
Use `Channel::from_wire_index` to decode an actual wire index; Events15 is None.
`graph::grants(child)` is an exact-size value iterator; all children still use
ordinary v1 startup with at most8 roles. NetDriver receives ports/window/RPC
receiver/Events; NetService gets distinct NIC/client windows, driver SEND,
client receiver and Events. App receives none of those new sources or endpoints.
Its first six grants are unchanged, followed by dedicated NoteWindow as role7.
File, Block and the network actors do not receive NoteWindow.

## Catalogue

V4 Root admission alone permits at most 240 image pages, 244 private owner slots
and 246 loader-owned private frames, within the unchanged 512-frame Root quota.
The layout record binds `EVRCAP04` at 944..952 and those three LEu64 limits
at 952..976; 976..1024 binds the RTC policy. Native3 retains 96/100/102 and ordinary
service/Desktop aliases retain 64 image pages/68 owner slots. Guarded stacks,
package windows and every page's permissions and charge remain independent.
The integrated acquisition component measured 198 image pages and a resolved
30,760/32,768-byte userspace stack before this metadata refinement. The prior
176-page ceiling refused that component. Size optimizations exceeded the stack
limit, and the medium address model failed high-address relocation checks.
ADR-0093 records this measured V4-only refinement and its required fresh selected
Kernel census, actual load/retirement and full-graph quota checks. These component
numbers alone establish none of those joined gates.

`catalogue::Description` encodes exactly4096bytes. The first1536 use the same
six-component wire layout with explicit v4 role counts[8,4,8,6,7,8]. They describe
the actual seven-role AppA, rather than an invented six-role shadow. Public
legacy catalogue encode/decode remain strict[8,4,8,6,6,8] and reject this App7
base. `root_v4::catalogue::encode_base` is the explicit producer entry. A v4
`base()` returns read-only `Components` validated by the private profile-count
constructor; it cannot stand in for a legacy-validated `Catalogue`. Its embedded
old Root ABI describes only that wire blueprint, never Root4 admission. The
authoritative2560-byte extension is:

|Extension offset|Meaning|
|---|---|
|0..16|EVNATV04/version4/length2560/profile4/reserved|
|16..48|v4 Root ABI|
|48..80|full v4 layout measurement|
|80..144|PackageB digest/build identity|
|144..160|exact A/B lengths,1..63pages|
|160..336|AppB ordinary image/descriptor/ABI/limits/7roles matching actualAppA|
|336..512|BadShell same8-role Shell contract, distinct image|
|512..514|Standalone0/SystemManaged1/Recovery2 configuration|
|514..520|reserved0|
|520..696|NetDriver image, ordinary v1 ABI,4roles,frame cap32|
|696..872|NetService image, ordinary v1 ABI,5roles,frame cap64|
|872..1000|device profile and actual source/binary witness digests|
|1000..1064|nominal PIT profile metadata|
|1064..1192|bounded periodic CPU/resource/operation policy|
|1192..1512|one DNS diagnostic name and independent TCP destination scope|
|1512..2536|exact1024-byte v4 layout description|
|2536..2560|reserved0|

The two network actor rows keep the176-byte ordinary image shape. Existing
children retain `[16384,32,1,1]` descriptor limits; NetService uses frame cap64.
Periodic execution is explicit in the v4 extension: each child64CPUticks per
256tick period, Root/parent256/256, preserving cumulative usage accounting.
This metadata does not configure the actual scheduler by itself. Root retains
its512frame budget. Actual linked images, stack census and physical ownership
must pass admission; declared caps are not estimates of actual use.

Device profile1 names selected QEMU ISA NE2000 byte PIO0x300..0x31f, polling
without new IRQ authority, MAC02:45:56:52:00:01,4RX/4TX slots, frame60..1514,
device-local packet RAM0x4000..0x8000. Nonzero source/binary digests name evidence
to join independently. They do not automatically qualify downstream QEMU source,
prove device-wide lack of DMA, supply entropy or attest host behavior.

Timer metadata describes current nominal QEMU PIT1193182Hz/divisor1193 and
millisecond conversion from delivered IRQ ticks. It supplies no trusted UTC,
precision or elapsed-wall-time guarantee across pause/lost interrupts. Runtime
seed provisioning must use an actually qualified provider, once through the
trusted Root-only initializer. No seed is stored in this immutable catalogue.
A fixed fixture Root epoch such as501 is not a unique cold-boot identity.

TCP scope is one unicastIPv4/remote port with ephemeral local port49152..65535;
the DNS name is canonical lowercaseASCII and at most253bytes. DNS diagnostics
and transfer destination are separate; an answer cannot widen destination
authority, authenticate the peer, establish TLS trust or authorize an update.
Actual Root must initialize the service with exactly the measured policy.

## Measurement and layout

Recompute the full catalogue measurement using `MEASUREMENT_DOMAIN`, the first
measurement slice,32zeros,the second slice, `layout_description()` and
`graph::description()`. Only the full-catalogue field1584..1616 is excluded.
`cohort_parts` additionally excludes the two BootMode bytes at2048..2050;
raw catalogue/manifest/admission still bind the actual mode. This content recipe
does not assert current generation selection, owner consent or health.

Root retains stack pages256..263 with guards255/264; children keep256..259 and
guards255/260. Package banks/guards remain A384..446/383,447 and B304..366/303,367.
Root mappings are system508/catalogue507/note506/new client505, four claims for
this v4 profile only. RootNote506 maps only dedicated source28; App maps that
same object at507 while retaining the independent AppFile object at508. Actual
factories must provide distinct objects/backing; core binding rejects a source
alias or a derived AppFile handle supplied as NoteWindow. This removes the
prototype's reliance on client cooperation for two independent loans of one
physical window. NetService maps its client window507 and NIC508; NetDriver
maps NIC508. These virtual aliases are per-process. Actual window objects remain
distinct, scoped and pinned by the canonical protected RPC path. Root role
triples begin at layout-description offset384. No physical pointer is serialized.

The8192tick cold-prepare prototype is outside accepted client work. Ordinary
Block/Present/Input/new Net RPC operations retain1024tick bounds. The four
File routes have an8192tick aggregate transaction cut; each child Block request
captures `min(parent,now+1024)` once before publication and never extends it
during Busy retries. Graph/layout/ABI measurements bind these distinct bounds.
The finite9728tick Note completion-retention policy is also included in layout;
it does not guarantee delivery or extend accepted I/O deadlines.
Full stop/scrub must be measured under
the actual policy, with explicit phased work if needed. No accepted operation
is retried or labelled quiescent just because its deadline elapsed.

The V4 Root cumulative limits are exactly `[65536,512,10,10]`: the actual
Root and eight children plus one held replacement. Boot retains its existing
CPU/frame limits `[262144,1024]` and selects10 process/thread slots only in V4.
Legacy profiles retain8. The actual child Jobs are siblings of RootJob under Boot, not charged to
Root512. Root246 plus child ceilings288 plus one held App32 sum to566 initial
private frames under Boot1024. Adding the separately charged dynamic table/control2
and two64-page owners gives partial Root376 and Boot696 subtotals. Shared RAM,
ROM package extents and all other retained owners still require actual charges;
these partial subtotals are not reservations or full physical peak proofs.
Layout words360/368/376 bind process10/thread10/held-replacement1.

## Read-only elapsed calendar source

Layout976..984 is `EVRTC004`, followed by five LEu64 values at984..1024:
index port0x70, data port0x71, century register0x32, original read cut512PIT
ticks and at most4 snapshots. The ABI also fixes8 bounded UIP polls per snapshot,
byte-only directions and coherent double snapshots. The source accepts consistent
BCD/binary and12/24h calendar values, rejects SET, stopped divider, invalid source,
invalid Gregorian dates, regression, overflow and an original cut reached during
a read. A failure fences this actual Root source; it never returns a cached
security-time sample or falls back to PIT/host UTC. No data-port write exists.

The reviewed Q35 model ignores index bit7; this adapter selects only register
indices below128. This is not a physical-machine NMI policy. RegisterD validity
is not evidence of host UTC quality. Calendar labels are reduced to elapsed
whole seconds with one-second floor resolution. A fresh qualified-CSPRNG domain
is created for this Root incarnation, not derived from the repeating catalogue
epoch. Exact host BOOTTIME/module launch, suspend/pause behavior and a justified
minimum rate remain independent qualification obligations. Only separately
verified fresh signed time may provide absolute UTC bounds; this profile alone
provides none. Kernel PIT scheduling and operation deadlines remain unchanged.

The downloaded-cohort private integration measured219 image pages and225
initial private frames after moving its one actual Root owner into the existing
scoped resident-claim discipline. Its resolved linked stack is31,272/32,768 bytes
with zero unresolved indirect calls. The earlier208 ceiling correctly refused
the new feature. ADR-0094 recorded the prior V4-only224/228/230 component. ADR-0098 now sets
240/244/246 for the measured automatic owner controller, preserving Root512-frame quota,
all actor/ancestor accounting, guarded stack sizes and operation cuts; selected
Kernel/guest resource census remains a separate gate.


ADR-0098 adds one measured16-page V4 image quantum after ADR-0094: the joined
owner baseline needs227 image pages, while the negative baseline needs224.
The240 ceiling leaves13 pages of maintenance headroom, while owner=image+4
and initial=image+6 remain. Only exact current V4 ABI/layout admission selects
it; old224 ABI/layout metadata refuses. Ordinary64/68 and Native3 96/100/102,
App/data ABI, W^X/guards, Root32KiB/Kernel256KiB stacks, CPU/IO/health cuts,
capabilities, children, Root512 and Boot1024 quotas are unchanged. A selected
full-source producer/census and actual owned VM qualification remain required.
