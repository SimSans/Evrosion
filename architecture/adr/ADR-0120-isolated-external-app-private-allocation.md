# ADR-0120 — Isolated external App private allocation

Status: Accepted Internal Level B refinement; native enrollment/join qualification pending.
Date: 2026-11-16
Related: ADR-0048/0049/0109/0110/0118/0119; INV-AUTH-001/002/004/008,
INV-IPC-004/005, INV-LIFE-001/002, INV-EVO-006; M8-09/11/12.

## Existing decision and observed problem

The existing RootSystem System, AppRegistry, AppData, GrantPolicy, SessionNote,
network checkpoint/content and original File regions remain owner data. In
particular physical64..77 and80..93 are the accepted0.2/0.3 registry/private
state. An external package's claimed AppId does not authorize reusing them.
The selected profile5 workspace occupies physical[16384,168706) on its declared
196608-sector owned disk. The source layout leaves an appended area after it.
Only an owned copy and actual blank checks can establish new allocation there;
a length, layout constant or parsing failure cannot prove that bytes are free.

The actual Store-v2 `open_mutable_namespace` checks the original immutable
creation manifest before generic recovery, but did not expose the pending
payload to the application-specific consumer until after replay. A host witness
in the retained SystemIo component demonstrates that matching creation alone
can replay a canonical envelope with another AppId. Post-open validation would
be too late to promise preservation of foreign pending payloads.

## Refinement

Add `Store::open_mutable_namespace_checked`. The trusted consumer validates the
committed payload and the exact checksum/base-bound pending mutable payload
before transition or any recovery write/flush. Failure returns the actual
borrowed device with no formatting or recovery publication. Original
constructors retain their behavior and disk formats do not change. The new
consumer is policy, never selected from media and never a capability check.

For the one declared external-App reference allocation, profile5's already
Root-owned SystemBlock receiver gains exactly these closed regions:

| Purpose | Wire sectors | Physical sectors |
|---|---|---|
| External registry |8192..8205|168720..168733|
| External private data |8208..8221|168736..168749|

Physical[168706,168720),168734..168735 and168750..168751 are explicit guards.
No original mapping, Workspace offset, Files route or profile4 mapping widens.
An ordinary packet supplies no AppId, region selector or raw physical address.
This is a bounded declared allocation pair, not a general multi-App allocator.

Root owns one affine SystemIo transport/window for the whole process lifetime.
The native adapter claims only the actual admitted Root startup and held
SystemBlock channel; it uses the existing fixed page508 window, unchanged8192
aggregate cut and1024 child cuts. No second wrapper, native reconstruction,
event pump across a borrow or alias to that mapping is permitted. Unknown
transport/reply completion fences every region and retains the exact request.

The fixed allocation ID `EVM8-EXTAPP-0001` and purpose-specific full creation
manifests are retained independently of package contents and mutable media.
They do not change when a later package is selected. The trusted enrollment
controller separately supplies the actual enrolled AppId/schema. Canonical
AppDataEnvelope validation fixes that AppId/schema for committed and pending
payloads, and pending replacement must advance its counter exactly once.
The PrivateData wrapper exposes no raw Store escape and returns success only
after exact whole-envelope readback. It retains the original operation and
frozen proposal on uncertain execution or readback.

## Enrollment and native integration obligations

Neither the descriptor, package claim/signature nor the I/O owner authorizes
installation or initialization. Actual protected owner development enrollment
must present the exact immutable package/build/AppId/schema and capability
effects, obtain fresh deliberate confirmation, establish that both new complete
regions are genuinely blank under sole ownership, and durably record the
canonical enrollment/creation identity. No fallback formatting follows an open,
identity, pending, foreign or corruption error. Partial allocation must retain
its exact record and enter explicit recovery instead of being called empty.
A later package with the same claimed AppId cannot inherit private data without
validated existing enrollment/update authorization.

Actual executable Register/Prepare/Start, old File61/service retirement,
reap/scrub and fresh per-incarnation sessions remain separate required joins.
ND requests require an actually admitted exact App session and its immutable
package's declared AppPrivateData contract/capability; actual sender/control and
registered incarnation are captured outside the bytes. Reserve a bounded exact
target reply before changing data, retain the unchanged request/service cut,
commit and independently read back before Value, and settle or explicitly fence
old reply debt before lifecycle changes. Do not advertise ND support until that
actual handler is loaded. Owner-development authorization is distinct from
publisher authenticity and official release trust.

The current source adds the checked-open mechanism, closed profile5 mapping,
Root-owned safe storage core and separate native claim adapter. It does not yet
implement protected enrollment, fresh formatting, canonical registry activation,
ND admission/reply handling or dynamic52 launch. This intermediate state is not
an installed/private-data service, native execution or an M8 gate PASS.

## Alternatives and qualification

Reusing old AppData would violate preservation and identity boundaries. A host
directory would bypass guest storage. Dropping pending-payload validation would
permit writes before consumer identity checks. A fresh arbitrary allocation
number would neither establish blank media nor explain future reclamation.
The additive pair keeps original scopes intact and uses the existing Store,
canonical lifecycle and Block mechanisms; larger allocation policy can evolve
with its own measured compatibility and preservation decision.

Test original/profile4/Files/Workspace mapping preservation and explicit guards;
actual Store checked-open no-write refusals before replay; exact AppId/schema/
creation, malformed and counter-bound pending payloads; native affine ownership
compile/linked stack/image budgets; actual protected enrollment/install/run,
ND reply backpressure/death/expiry, cold readback and update/service failures.
Original volumes and evidence stay unchanged. Host component tests, a claimed
layout or successful strict compilation alone close no gate.
