# ADR-0069 — V4 network graph admission

Status: Accepted mechanism; joined runtime and device qualification incomplete

Date: 2026-11-12

Decision level: B

## Context

The six-service Native3 graph has no scoped network service or device actor.
Appending grants without versioning its metadata would either widen old callers
silently or let a seven-role App description masquerade as a validated legacy
six-role component. Its eight-process parent limits also cannot admit Root plus
eight children and a held replacement.

## Decision

Use the explicit V4 SDK/Core profile and `test-m6-network` factory. Its measured
Root manifest has28 sources,1104bytes, and a912-byte startup record with capacity
for32 grants. Its full catalogue is4096bytes. Preserve Native3, Desktop and all
finite encodings and verifiers. The legacy component catalogue exposes a
read-only component view; only V4 encoding/admission accepts the actual App's
seventh Note role. No copied or reencoded legacy shadow stands in for V4.

The canonical retained Kernel graph executor admits eight children and18 wires.
The first six child identities retain their positions. NetDriver and NetService
follow them, using explicit wire indices16 and17; Events remains15. Decode wire
indices through the typed sparse conversion rather than assuming they index a
dense channel list. Image/Job/frame/grant admission uses each actual child's
limits and descriptor. No second IPC, lifecycle, mapping or authority engine is
introduced for the network profile.

Source25 grants only byte-port access to0x300..0x31f. The initial ISA NE2000
profile polls the device with its interrupts masked and receives no guest-memory
DMA, IRQ or PCI authority. Sources26/27/28 allocate three independently owned,
zeroed, readback-checked MemoryObjects for NIC transfer, the Root network client
and Notes. Root maps Client505 and Note506; the App maps distinct Note507 and
File508. NetService shares NIC508 and Client507; NetDriver has only NIC508.
Existing lease/claim owners validate and retire those actual mappings.

V4 Root limits are65536 CPU ticks,512 frames,10 processes and10 threads. Its Boot
ancestor retains262144/1024 CPU/frame limits and changes only process/thread
capacity to10. Nine live slots cover Root and eight children; the tenth is one
explicit held replacement for existing activation ordering. There is no general
abuse reserve or cumulative-accounting reset. Existing finite ancestors retain
eight process/thread slots. Conservative Root frame admission sums288 declared
child frames,32 for the held App and105 for Root, totaling425 below512; actual
linked/runtime measurements remain required. Both ancestor process and thread
limits must refuse the next admission atomically.

The trusted V4 Registry installs exactly two finite Job templates before any
userspace call: template0 is16384/32/1/1 and template1 is16384/64/1/1. The typed
graph selects1 only for NetService; all other children select0. The template
table and each child's selection/limits are bound in the V4 layout, graph and
ABI measurements. Existing Registry constructors expose only template0 with
their original limits. CREATE_JOB accepts an installed ID, never arbitrary
limits; CREATE_PROCESS still compares actual Job limits to the registered image
and charges every ancestor. Unknown IDs, wrong authority, late capability
exhaustion, image mismatch and exhausted parent budget refuse without committing
partial scheduler/authority/Registry state.

Network actor faults capture actual provenance and terminate only the faulted
thread. Canonical peer-death and descendant drain rules settle CPU/RPC custody.
Both network participants retain their image/window/device owners and a latched
hardware debt forbids reap/recreation. This is containment with unavailable
networking, not proof that the NIC stopped or packet RAM is safe to reuse.
An actual optional network actor's voluntary Exit follows the same retained
hardware-debt and canonical peer-death path, with a distinct actual PID/TID,
exit code, instruction and tick observation. It creates no fault capsule or
fault count and does not alias the App's voluntary-exit record. Legacy critical
service Exit behavior is unchanged. The first exit/fault class remains retained
separately from the shared obligation that blocks both network participants.
Actual trusted STOP/reset/drain/scrub and safe retirement remain M6 requirements.
Sustained sessions accept classified ordinary App faults without requiring the
old demonstration's exact page-fault vector/address.

The initial V4 consumer explicitly supports Standalone only. Unsupported System
generation creation and Managed/Recovery execution refuse before mutation.
New registry/data/grant creation uses the actual admitted Root ABI; Notes retain
their separate stable format ABI and historical creation context. The eventual
V4 System recipe and authenticated update/recovery path are separate mandatory
engineering work, not satisfied by a catalogue facade.

The source-built producer retains and admits the actual eight binaries, both
App containers and their role/limit measurements. A tracked QEMU reference
witness is a fixed build input so the build host's installed binary cannot
silently change the OS artifact. Its explicit qualification field starts false;
a source hash or emulator hash alone proves neither downstream model equivalence
nor entropy. The runner must join actual invocation/binary/provider evidence
before positive device or entropy qualification.

## Validation and remaining work

SDK87, session-feature Core428 and Root68 focused checks pass in their retained
receipts, together with strict target checks and exact ancestor saturation tests.
Legacy serializer goldens remain unchanged. The source package facade validates
real serialized A/B backing, both measurements, role counts, limits, authority,
ABI and Standalone mode, including substitution/refusal tests.

A pre-factory linked ELF had its graph optimized away and is explicitly not a
V4 stack admission result. Repeat the real256KiB Kernel stack census with the
actual selecting factory and real assets before VM execution. Source Root's
V4 bootstrap/controller, NIC operation, runtime entropy/time, unauthorized-client
denial, link/fault/backpressure paths and safe final retirement remain open.

The subsequent source03/c8cf partial static checkpoint linked the selecting
eight-actor factory and measured254864 of262144 bytes with world::run reachable.
That historical checkpoint predates the two-template refinement; its image build
initially stopped at an incomplete offline cache. The fresh source-identical
run05 completed image/manifest creation with the full three-lock cache closure
and the same Kernel bytes/census. Its wrapper's receipt-name collision is retained
separately from the verified actual build and census. Neither checkpoint is a
guest execution or a stack admission result for later source changes. Repeat
the actual linked census after the current Registry and network-exit changes.
