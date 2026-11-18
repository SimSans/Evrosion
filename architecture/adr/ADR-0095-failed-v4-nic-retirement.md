# ADR-0095 — Failed V4 NIC retirement through the captured Root

Status: Private Level B implementation refinement; host checks pass, actual linked resource and VM acceptance pending.

Date: 2026-11-13.

The permanent failed-network latch correctly retained both NIC actors after an
unexpected CPU death. It also prevented complete retirement indefinitely. A
thread exit, timeout, diagnostic failure row or host termination cannot establish
that the live NE2000 has stopped or its device-local packet RAM is clean.

Use the existing captured V4 Root, its two actual Process CONTROL capabilities
and its existing explicit `NicPorts` capability. No actor, object, grant, DMA
assumption, stack or quota is added. Only the selected non-DMA ISA NE2000 path is
covered. This is quiescent retirement, never automatic driver reconstruction.

This first path requires both actual Driver and Service actors to have been
created and admitted. A Driver startup death before Service creation has no
Service CONTROL to authenticate. That case retains debt and all extant owners;
it cannot arm operation53, and no missing process/control/PID is fabricated.
Single-actor startup-failure retirement is a separate unsupported case in this
prototype. The required live-pair queued-work tests do not qualify it.

The Root first stops both actual NIC CPUs using the ordinary process-control
path. Accepted nested calls retain their original cuts and shared-memory credit
until canonical leaf death/completion/withdrawal. STOP refuses while that ledger
is nonempty. The cleanup does not reinterpret a timeout as permission to reuse a
window or packet, and ordinary local App/File/Note work remains independent.

V4-only scalar operation53 begins the separate retirement transaction. Only the
actual captured Root can name the exact current Driver and Service controls.
Core requires both threads Exited, both Running image owners returned, no serving
RPC, no retained Pending touching either actor, and both actual NIC queues closed
and empty. It captures the process/thread pair and one original finite cut of at
most8192 ticks. The returned scalar token is scoped to this one Root and failed
graph; it is not a capability or caller-provided process identity.

After this exclusion join, the Root constructs `Recovery<Mediated>` from its fixed
actual `NicPorts` role. The userspace driver immediately asserts physical STOP,
restores byte mode and the device-local RAM wrap bounds, checks those bounds,
and writes zero then independently reads every byte of the whole16KiB RAM in128
distinct128-byte chunks. Every chunk retains the existing physical accounting,
yield boundaries, original aggregate cut and child cut of at most1024 ticks
(Root chooses512). STOP and bounds are freshly read before and after every
chunk. No RESET or START command is issued. A fresh Rust owner never pretends
that the old driver's private state survived its death.

Only the final complete physical readback produces move-only `Stopped<Mediated>`.
Unknown or partial I/O retains the exact recovery owner and permanently prevents
automatic retry. The new projection consumes the exact witness in State::recovered
before invoking its sealed private operation53 completion adapter. Core rechecks
the same captured pair/token/original cut and all actual exclusion/queue conditions.
Only a successful join changes State from Unavailable to Stopped; failed completion
keeps it unavailable. This tightens the original frozen prototype's retained-proof
ordering without changing that evidence. Core then permits retirement of the
old owners. Their original failure/voluntary-exit classification stays immutable;
creation in either failed NIC slot remains forbidden for this Root incarnation.

The physical proof boundary is the same sealed, source-bound trusted Root and
userspace Driver boundary used by nominal NW7. Core independently proves actual
process/capability/queue conditions, not the NE2000 protocol. The scalar token or
Kernel diagnostic row alone is not a physical witness; no App, event body,
arbitrary Ports implementation or reported byte count can enter the Root's
private completion adapter. Actual execution still has to join the reviewed
source and scoped PIO results with the final Kernel retirement receipts.

The Root already held the declared byte-I/O capability over0x300..0x31f; this path
now actively uses it during failed-device cleanup. That trusted Root authority
is explicit in its original V4 graph. It does not receive ambient IOPL, raw in/out
instructions or additional port ranges. An additional V4 profile gate admits
Root NIC I/O only while operation53 has armed this exclusive pair and its original
cut is still live. NIC I/O from every other actor is denied after failure; after
the completed join Root NIC I/O is denied too. Every scalar and Word4 branch
still performs the canonical actual IoPorts capability, width, direction, range,
lineage and running Scheduler/RPC checks before hardware access. Local ATA,
Input, RTC and UART authority keeps its existing checks.

The Root's own port capability remains open until normal Root/Kernel teardown;
cleanup does not claim to revoke that retained high-water object. Its exercise
is constrained by the additional armed-stage gate. Old stopped CPUs cannot
obtain an actual Scheduler/RPC-bound PIO permit, and no replacement is dispatched.

One bounded physical chunk runs per ordinary Root turn. It does not wait for a
network response or return early from unrelated owner work. Recovery failure
retains hardware/image/window owners; such a failure is not a successful
containment/retirement result or a reason to accept a terminal VM abort.

Focused host tests cover hostile old byte/wrap state, all128 actual model chunks,
early finish, false bounds, corrupted first/middle/last readback, unknown I/O,
expired/reversed time, no retry, wrong pair/token, one-shot original cut, retained
failure classification and permanent no-recreate. These checks do not establish
the actual captured Runtime exclusion gate, local GUI continuity, queued-work
failure containment, physical device retirement or release acceptance. Fresh
actual Root/Kernel resource censuses and separately pinned Driver/Service death
VMs with real outstanding work are required next.
