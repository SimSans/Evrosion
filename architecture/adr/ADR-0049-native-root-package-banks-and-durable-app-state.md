# ADR-0049 — Native Root package banks and durable App state

Status: Accepted bounded implementation direction; physical native lifecycle
pending. Date: 2026-10-27. Documented mechanism refinement; no foundational change.

M4 now proves the real graphical service graph. Its Root profile has eighteen
sources, one App executable and one measured package identity. Root cannot read
a complete package merely because the kernel contains its bytes. System health,
File contents and native activation state must also have separate durable owners.
Reusing the health probe payload or calling a metadata model an installer would
violate the existing lifetime and recovery guarantees.

Native Root therefore has an explicit additive profile 2: the same bounded
720-byte Root-only startup format, a distinct ABI, exactly twenty-one sources
and an 880-byte measured manifest. The original eighteen retain their meanings;
three added sources are the alternate App image and complete readonly package
A/B banks. The existing Custodian/binding/activation engine owns the one actual
Root incarnation. Typed profile validation selects known roles/ABI, preserving
the original profile 1 and ordinary 336-byte/eight-role service contracts.
Spare capacity is never permission to accept arbitrary roles.

The native readonly catalogue is 2048 bytes. Its legacy 1536-byte section is
component/A metadata; the explicit extension supplies authoritative native ABI,
profile/layout measurement, alternate executable descriptor and complete package
digests/lengths. Consumers validate the full native catalogue and reconstruct the
native manifest; they cannot use the embedded desktop ABI to admit Native Root.
Both complete banks must fit the declared 63-page bounds, be initialized,
hashed/read back and mapped RO/NX into held Root with guards. Parent accounting
charges their actual owned RAM once. An outer executable owner retains the real
mapping leases while Active excludes mutation; no live metadata/table copy or
extra authority engine is introduced.

Native System uses three closed logical slices on the same serialized Root
transport/window: System 0..13 maps to physical 16..29, registry 16..29 to 64..77,
and App data 32..45 to 80..93. Holes/overflow refuse. Existing Desktop System
and File mappings remain unchanged. A registry head is the canonical Record256;
private data is a separate AppId/schema/counter/value envelope. Removal retains
the tombstone and private data. An epoch is not evidence that data exists or was
migrated. No migration operation is exposed before an actual data-owner receipt.

The trusted owner resolves actual immutable package bytes, requirements,
executable/descriptor and current data schema. Staging does not replace running
code. Activation prepares an exact revision/head transition, quiesces the old
App, settles shared calls/messages, revokes its default grants and retires its
image before any new incarnation uses those resources. A measured compatible
candidate is held before durable publication; successful publication/readback
precedes Start. Failure stays explicit: recover an uncertain operation before
reuse, never infer nonexecution, erase data or allocate another operation ID to
retry an unresolved write. Cold startup revalidates the actual committed head.

App private-data requests are versioned typed scalar messages on this native
profile's existing routes. Root authenticates the actual current sender and
registered namespace; an App supplies no sector, global operation ID, foreign
AppId or permission epoch. Each request's durable reply follows actual storage
completion/readback. This asynchronous exchange is not claimed as protected
synchronous RPC. The first compatible schema has no migration.

Alternatives rejected for this slice are widening every process table, adding
provider actors to the desktop solely for a separate conformance proof, exposing
generic Block to Apps, overwriting System/File data, or creating a new filesystem.
Source-built immutable banks are deliberate development deployment, not general
disk import, publisher authentication or official-store authority. Their memory
cost and final Root/actor stack footprints must be measured before execution;
no stack/pool growth is implied by this ADR.

Acceptance requires actual install/activate/update/rollback/remove/reinstall,
old-owner retirement, compatible actual A/B execution, retained private data
and cold reads with independent whole-disk guard checks. Model interruption
tests support the publication primitive; they do not certify dead-guest retry
intent or host power loss. Native generation health must be separately composed
with the existing M3 mechanism; GUI readiness cannot assert Known Good. Joined
actual crash context, Job inspection, live provider replacement and the complete
0.1 demonstration remain separate required execution proofs.

Native state diagnostics use bounded frames over the existing authenticated Root
Events endpoint. Ordinary four-slot queue acceptance/delivery remains unchanged;
one retained report advances incrementally while Root drains its inbox, and
owner command parsing waits for the complete report. The executor validates
frame order/sequence and binds the actual Root sender plus current App identity
at accepted Begin. Only a complete report becomes one diagnostic output line.
Source claims remain independently checked against actual image/process actions
and cold disk snapshots; a report cannot authorize a grant, establish health or
stand in for durable completion. This removes competing bytewise UART writers
without adding a syscall, raw userspace pointer or authority engine. UART owner
commands remain complete bounded lines. Cold startup completes its no-App open
report before admitting the installed App, preserving that report's identity.

The first physical Native Root exceeded its existing 16 KiB userspace stack
before Home (recorded failure, 2026-11-11). A decoded fixed-capacity Entry array
inside every parsed Package caused repeated copies, and boot/storage temporaries
remained live in nested runtime frames. The package view now borrows its already
validated immutable index rather than retaining all decoded Entry values; every
row and content hash is still checked eagerly before parse succeeds. Public
getters, borrowing/compatibility guarantees and container bytes remain unchanged.
The host view measures352 bytes; maximum-entry/corrupt-last-resource and existing
immutability tests cover this representation. The controller/Store ownership
repair is measured against actual linked source Root with the unchanged16KiB
guard. No larger stack or weaker admission rule is authorized by this failure.

[ADR-0050](ADR-0050-measured-native-root-stack-budget.md) supersedes the initial
no-stack-growth assumption for Native Root only, after actual failure and
measured copy reductions. The Native Root now has an explicit guarded32KiB
private stack, within the unchanged Root quota; Desktop/services/apps remain16KiB.

The instrumented Native32 run then reached Home/install A but exhausted its
finite bound inside SHA256 before candidate start. All186 calls had completed
and every wire queue was empty. Repeatedly parsing the same sealed banks was
avoidable work. Native Root now retains the two completely parsed immutable
Package views after initial verification. The registry accepts an optional view
only when its full backing pointer and length match the current resolver bytes;
otherwise it performs a fresh complete parse. Full package/App identities,
current ABI/platform/contracts, schemas and declarations are still checked on
use. Private parsed fields and immutable borrows prevent metadata substitution;
actual ELF admission, scoped grants and bank sealing remain separate gates.
Tests reject missing, corrupt, substituted and shortened backing slices as well
as changed host policy. This changes neither package bytes nor authority rules.

Live diagnostics now have a separate authenticated sourceRoot NC416/NJ192/NS384
stream, one global report serial and one ordinary SEND attempt per fair tick.
Full actual FaultInfo is collected before reap and independently joined with the
Kernel's raw24-word trap snapshot and retained Root binding/image provenance.
Inspector rows query actual Job controls, retain separate observation intervals
and are checked against bounded actual query receipts, including wrong-kind and
stale-cap refusals. System inspection forbids writes/flushes even during Store
recovery; unformatted metadata and unavailable current admission remain explicit.
Crash416 stays in a bounded two-capsule RAM archive plus create-new host artifacts;
it is never truncated into the Store's256-byte mutable payload. The Native-only
UART counter is512KiB for bounded query/payload receipts, with no allocated log
buffer; oldDesktop keeps256KiB. This adds no authority or health signal. Actual
joined physical diagnostics acceptance remains pending the new source-frozen run.
