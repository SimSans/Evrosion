# ADR-0081 — Owned dynamic executable admission

Status: accepted Level B mechanism; Kernel HAL/source frontend implemented,
selected linked census and actual downloaded execution pending.
Date: 2026-11-12.

## Problem and boundary

[M6-07](../M6_PLAN.md) requires cold execution of authenticated persisted
content genuinely absent from compiled package banks. A copied bank descriptor,
publisher signature, durable object or host file replacement cannot establish
that gate. The existing service registry stores borrowed compiled ELF bytes;
placing a borrow of runtime-owned code in that registry would create a
self-reference or require a fabricated lifetime.

Keep release policy and Zion/package interpretation in userspace. Extend the
existing Core extent, capability, service and checked lifecycle mechanisms.
This decision adds no authority object kind, grant, allocator, independent
registry, scheduler or admission bypass. It does not change accepted update,
owner-control, isolation, recovery or power guarantees.

## Charged staging and seal

An opaque permit borrows the actual active Root V4 binding. Every operation
rechecks its current incarnation, live destination, actual Root process/Job,
measured limits and installed CreatorJob CONTROL capability's exact two-hop
lineage. Admission-only exact destination-table checks are not reused after
Root legitimately creates child handles. Legacy, revoked, dead or foreign
bindings do not mint this permit; caller-provided PID/Job/boolean substitutes
are absent.

Staging owns at most64 actual allocator frames charged to that Root Job and its
ancestors. Initialization performs zero write/readback. Before any mapping,
the retained unmapped frame set is sorted and physical adjacency is proved.
Fragmentation refuses explicitly and returns the same owner for cleanup; no
contiguity or Root virtual-address cast is assumed.

Only Root receives a RW/NX mapping capability without DERIVE or TRANSFER.
Sequential progress accepts nonempty chunks of at most4096bytes under one
original finite monotonic cut. Progress is not evidence of written bytes.
The hardware adapter must implement the unsafe `Mappings` contract against
the captured address-space owner: fixed guarded V4 window, exact physical
pages, PTE readback and complete relevant TLB invalidation. It must remove
every writable alias before returning success, including partial installation.
An unknown hardware result retains the original lease and fences the owner.

Seal preflights closing the writer and deriving READ|MAP in the same freed
Root handle slot, then removes actual mutable aliases and returns the writer
lease. This conversion works with all64 Root handles and authority objects
occupied. It does not require a temporary65th handle or publish a new object.
Only after removal does bounded physical readback hash the whole declared
package and its ELF subrange and reject nonzero physical tail padding.
The final transition rechecks actual authority, time and both hashes.
There is no unseal or mutable sealed-extent accessor.

## Existing registry and lifecycle

Use the same16 image rows. A dynamic row stores an opaque extent/backing
identity and four validated image coordinates, alongside the existing
descriptor policy. It stores no per-page64-entry plan and no byte reference.
The only dynamic descriptor is the existing V4 seven-role App template with
its exact App resource limits, service ABI and ordinary W^X/guard parser.
Packet-nominated roles, rights, limits or layout are not accepted. Root binds
the expected descriptor and hashes only after its package/release checks;
these Core measurements do not authenticate a publisher.

Registration pins the same affine sealed owner after all checks and capacity
preflight. Existing process creation still validates actual image capability
and exact Job limits and charges private frames. Loading resolves a short
immutable byte borrow from that exact pinned owner through the trusted RAM
view; a second valid byte-identical sealed object cannot substitute for it.
Existing start/startup validation checks the cached image coordinates against
the actual loaded owner. The legacy compiled-image API cannot resolve a
dynamic image or fall back to bank bytes.

Unregister refuses while any held, active or retired process row references
the image. Existing stopped retirement and explicit forgetting must first
close domains/handles and balance physical charges. Unregister is logical;
it does not itself release RAM. Root package/resource parsing can borrow the
whole sealed package from the same actual RAM view. Move-only readonly
mapping leases independently prevent physical retirement, including after
unregister. The bounded B/C profile may retain two immutable Root package
mappings until Root exit. Runtime must retain those actual leases and remove
their hardware mappings before returning them; neither revocation nor a
metadata flag alone proves PTE/TLB quiescence.

Normal shutdown and unexpected Root death cannot depend on a still-live user
permit. A separate trusted stopped-owner unregister derives its coordinates
only from the sealed owner's private generational Root identity. It requires
actual Root termination, closed authority domain, the same retained Scheduler
Job and no remaining process row for that image. It removes only the exact
registry row/pin. This runs before reclaiming Root's Scheduler descriptors;
actual readonly PTE/TLB detachment and lease return still precede physical
release. A closed domain alone, termination alone, a foreign registry/object,
wrong Job or a held/retired source reference cannot authorize this cleanup.

Cleanup is explicit. Failed transitions return the actual uninitialized,
initialized, staging, sealing, sealed or retired owner. Partial mappings,
unknown I/O and quota remain retained until actual removal, destruction,
scrub/readback and frame return succeed. Dropping a token is never treated
as physical cleanup or permission to reuse its frames.

## Bounded resource implications

Current V4 Root starts with29 sources. The ordinary full graph retains17
channel handles and eight child Job plus eight Process handles:62 of64.
Two retained dynamic objects can occupy the remaining two slots. The writer
replacement uses the same slot. This is a reference-profile accounting bound,
not an observed peak or permission to overlap another held replacement.
With both objects retained and all eight actors present, another Job/Process
pair must refuse unless the existing App slot has first retired or an explicit
measured profile refinement is approved. No capacity is silently raised.

Two maximum extents add128 frames to actual Root Job and ancestor accounting.
The existing compiled cohort, surfaces, package banks and child private
frames remain charged to their real owners. Runtime must measure the actual
parent peak, Root64-slot/object bounds, return-queue headroom and exact linked
Kernel256KiB and Root32KiB stack censuses. This portable mechanism does not
increase these bounds or establish that the final composed profile fits.

## Verification and remaining integration

Portable tests use real Authority, Custodian, Root V4 binding, Scheduler,
MemoryExtent, service registry and checked held/start/stop/forget lifecycle
with explicit RAM/page-table models. They cover maximum64-page ownership,
quota refusal, fragmented allocation, whole-package/ELF hashes and padding,
malformed/W+X ELF, descriptor refusal, exact registered-owner binding,
registry capacity atomicity, same-slot seal at full64-slot/object capacity,
revoked/dead Root authority, stale progress/deadline, partial installation and
unknown removal debt, stopped-Root cleanup and readonly readers blocking
retirement even after logical unregistration.

These tests are not physical mapping, guest execution or M6 acceptance.
Next integration must supply fixed V4 mapping windows, captured actual RAM
and PTE/TLB adapters, bounded wire operations and live incarnation dispatch;
then stream authenticated content from the real arena, parse its real sealed
Zion package, admit it through this existing lifecycle and execute it after a
cold boot. Healthy downloaded B and pre-health bad C must remain absent from
Kernel banks. Their probation/rollback predicate must cover the actual
critical cohort, preserve the same data and permission bindings, and keep
replay floors separate from authorized local KnownGood recovery.

## Captured V4 hardware bridge

The V4-only runtime now retains one lazy private PT at Root PD1 (the next2MiB
region) and one private control frame. These2 external frames are explicitly
charged to actual RootJob/Boot under unchanged512/1024 limits, separately from
the initial LoadedImage124-page/130-frame ceiling. This avoids reserving low
code-growth holes or changing ordinary service/ELF2MiB admission. No capability,
object kind, grant or startup source is added. The exact fixed PT entries are
RO B1..64, RO C67..130, control192 RW/NX and sole staging256..319 RW/NX; unused
tails, guards0/65/66/131/191/193/255/320/511 and all other entries remain zero.

A narrow captured-Root guard validates actual controller CR3 equality, IF0,
PCID/LA57 off, retained table identity and the sole user branch. It does not
pretend that an admitted Root is held/stopped or expose general image mutation.
Actual volatile PTE writes/readback precede any success. Mutable staging aliases
are removed before Core's writer→RO transition; both low private PT and high
table are checked for surviving writable aliases. All user leaves are nonglobal.
MOV CR3 with PCID disabled invalidates the relevant nonglobal TLB and paging
structure caches; the actual capture restored controller CR3, updates reload
it, every Root resume reloads its own CR3 and APs remain parked. This uses the
[Intel SDM Volume3A, section4.10.4.1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf)
contract; INVLPG under an unrelated address space alone is not substituted.

The private readonly receipt owns its actual lease, physical/root/PT identity,
window and partial state. Stopped teardown removes and reads back every actual
PTE and establishes the CR3/TLB boundary before returning the logical lease.
Partial attachment/detachment retains that receipt; unknown publication inhibits
actual Root dispatch and retains all owners. Bare lease return is never a Root
syscall. Unsealed Stage/Sealing owners use their existing abort path after Root
death; registered owners use the stopped unregister gate. All physical release
still requires scrub/readback and actual allocator/quota return. The bounded
recycle queue's headroom is an actual composed teardown gate, not inferred from
the larger Boot frame quota.

Producer measurements report the two lazy external frames and at most128 code
owner frames separately from the initial LoadedImage ceiling. These are charged
under the unchanged actual Root512/Boot1024 ancestor quotas. The sum of every
declared simultaneous maximum is not reserved: exhaustion refuses without
dropping retained owners. Actual fixture measurements use ImagePlan units:
downloaded B24 image/30 private pages and C8 image/14 private pages; they do not
stand in for the final live parent peak or allocator recycle headroom.

Two potentially large64-frame owners live in one private Kernel resident slot,
claimed once atomically and initialized in place with an exhaustive field list.
It returns a unique reference scoped to the actual world execution marker;
there is no reset, automatic Drop or fabricated static code slice. The slot
contains owned tokens, not self-referential package bytes. Short Kernel ELF
views use retained sealed physical RAM and shared Authority/Scheduler borrows
that exclude destruction/release while in use. Actual loaded App frames are
copied through the existing GraphicsImage loader and checked service lifecycle.
Dynamic image selection/action/provenance has its own identity branch and does
not label downloaded content as compiled bankB.

Internal syscall52 IMAGE_CONTROL uses the existing four-scalar call convention
and a canonical256B header copied from the exact retained private control frame.
There is no user pointer, caller PID/Job, nominated policy/rights or device
description. Only Initialize creates the2 external frames. Root/CreatorJob are
revalidated at each capture; the original Stage cut is never renewed. Begin
returns the actual writer handle, and final Verify returns the converted actual
RO handle. Other positive replies are scalar; errors clear capability/serial.
Only typed operations0..8 decode; observing user-operation+1 cannot wrap into
the Kernel-only cleanup event0.49..51 remain unknown/unallocated. A24-byte
canonical geometry record uses the former final reserved catalogue bytes;
catalogue4096, layout1024, startup912,29 sources and manifest1136 stay unchanged.
V4 ABI/measurement binds this record and the explicit protocol description;
legacy byte goldens remain unchanged.

The pure SDK App7 descriptor transcript lets userspace bind a signed target's
contract without a hash dependency or admission authority. Core independently
checks actual sealed ELF and computes its descriptor; their digests are crossed
in a real Core test. Kernel observation labels package ID as DECLARED because
Kernel has not parsed Zion. Verified bytes/content/ELF hashes appear only after
the actual opaque Core seal; flags or source progress are not execution proof.

SourceRoot's non-Clone Images<actual KernelIo> frontend now calls Initialize
and3 Inspect fields after the common graph, before NIC startup. It has bounded
4KiB stream/Seal/Verify APIs and a scoped callback parsing only permanent RO
package bytes, checking actual Zion ID, ELF hash/range and expected Header.
Controller resident initialization retains this owner without a256KiB buffer,
mutable Package borrow or fabricated static reference. Acquisition/Controller
Stage/Activate wiring and cold authenticated B/C execution remain pending.

Portable Core/codec/model checks and strict target compilation cover this source
checkpoint; exact selected Kernel256KiB and Root32KiB censuses, actual resource
peaks, live PTE/retirement execution and same-disk cold recovery are still
required before the hardware/update acceptance claim.
