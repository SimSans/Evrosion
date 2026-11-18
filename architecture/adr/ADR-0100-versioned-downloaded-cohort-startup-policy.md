# ADR-0100 — Versioned downloaded-cohort startup policy

Status: Accepted Level B private implementation refinement. Models, integrated
resources and actual new-policy qualification are separate evidence gates.

## Problem and authority

The downloaded cohort adopted the initial M3/Native3 one64-tick health window in
ADR0092. Its critical subject additionally validates protected Scalar/Note data,
paints its saved view, completes a protected Present, and sends authenticated
CriticalReady. Those checks are essential; a signature, GenericReady, earlier
frame or synthetic completion cannot replace them.

Actual diagnostic05 retained the current admitted B identity and a closed12-row,
zero-overflow prefix. Relative to the first actual Root LIVE after Admission,
Note delivered at+36, the first App Present was accepted at+68 and completed at+69,
and genuine AppDone/Critical were accepted at+71. It correctly failed the old64
contract. These are delivered-IRQ ticks, not a physical CPU-time breakdown. The
actual painter already has inlined/unrolled stores; an unmeasured inline change
would not explain the failure.

An independent model using the actual Core Scheduler also demonstrates a legal
required-child64/256 phase: after64 legitimate CPU ticks it remains Ready with no
credit for192 more elapsed ticks while Boot still has192 credits. Quota ceilings
alone cannot guarantee even one more Display instruction within64 ticks of an
unrelated health anchor. This is a legal-state counterexample, not a claim that
quota exhaustion caused diagnostic05.

[E-012.40](../plans/platform/E-012-boot-and-recovery.txt) requires bounded watchdog
failure/recovery, without mandating64 universally. [ADR0052](ADR-0052-native-system-health-and-durable-owner-grants.md)
explicitly permits a separately versioned measured budget. The founder engineering
mandate Level B permits this mechanism refinement while preserving genuine
health, owner control, durable data and recoverability. This decision supersedes
only ADR0092's downloaded-cohort v1 timing. The original M3 and Native3 v1/64
contracts and their verifiers remain unchanged.

## Decision

The M6 downloaded System cohort uses health_version2 and a distinct
`evrosion.V4.downloaded-cohort.health.v2` description/hash. The first fresh actual
Root LIVE after durable Admission fixes one deadline:
`min(checked(anchor + 512), original_cut)`. Overflow, a nonfuture cut or invalid
clock refuses. No startup event, duplicate observation, packet, report, retry or
probe renews the deadline. Progress at the deadline is late. An earlier original
cut shortens probation; it never creates more time. The original8192 storage
cut and all child/RPC/producer/NIC cuts stay unchanged.

512 is two existing256-tick CPU periods. It accommodates the concrete192-tick
availability delay with a bounded additional allowance for this fixed graph.
1024 would add two more periods before declaring failure, without current
evidence requiring that delay. Neither number is a hard-real-time success
promise: CPU allowances are ceilings, not reserved minimum service. This is an
explicit finite failure policy for the qualified fixed cohort. A sufficiently
slow but authentic candidate may still fail and recover to protected Known Good.

All seven actual current startup/liveness identities remain required. Only Root,
Shell and the downloaded subject provide their genuine Critical progress. The
subject still validates startup/grants and protected initial reads and completes
its actual Present before emitting Critical. Timely critical progress does not
itself establish Known Good: the real durable System probe/write/flush/readback
and fresh LIVE of all seven remain mandatory within the original cut. System
Health commits before the authenticated content KnownGood publication and before
releasing the probation write fence. Actual child faults, Root ProcessFault and
live MissingProgress remain distinct; attempts, serials, identities and durable
failure evidence keep their original bindings.

## Contract and compatibility

Both canonical downloaded transcripts have v2 domains and explicitly bind the
health u16 version and description hash. The recipe then binds the existing
catalogue recipe, V4/App ABI, seven actual images, content identities, object
length and generation. Admission then binds the cohort, immutable bootstrap
manifest, actual Root/subject images, generation/serial, epoch/incarnation and
actual Root/subject PID/TID. Host reconstructs both independently; the public
Root/App ABI fingerprints do not change for this separate health manifest.

General Store and diagnostic readers support only health versions1 and2 in their
existing u16 fields. Store still compares the exact health version AND hash,
cohort, image, ABI, process stamp and serial against the selected immutable
manifest. General parsing is not policy authority. Downloaded v2 resolvers and
Host joins require their exact v2 manifest; they refuse v1 or another v2 health
hash, rather than assigning the new timing to old evidence. M3 catalogues,
Native3 health, creation-only manifests and their old consumers stay strict v1.
Store records, payload offsets, diagnostic Snapshot wirev2/framing, App/Note
schemas and EVACQ002 content checkpoints retain their existing formats.

Experimental v1 disks and failed-run evidence remain preserved. Refusal performs
no formatting, policy migration, attempt reset, remote-floor reset or translation
of an old KnownGood receipt. No v1 health is reinterpreted as v2 health. New
qualification uses new owned test disks; existing owner data identities and
content/publisher authorization remain separately checked. Local recovery still
needs no fresh remote time and never resets remote security floors.

## Evidence and adoption gates

Nonvacuous paired models require Generic for all7 and Critical Root/Shell only
before testing subject Critical at+511 (Ready) versus+512 (deadline refusal,
notReady, real-live MissingProgress). Both constructors, early original cuts,
clock overflow/reversal, foreign/stale identities and v1/hash swaps are checked.
The unchanged actual legacy critical-progress Window must still pass+63 and
fail+64. Durable probe/live checks can finish later only under the original cut.

Actual Core scheduling models sweep all256 phase offsets and residual0/1/64
where a serialized BSP can genuinely have consumed the prior ticks; impossible
early-period exhausted states are not fabricated. They retain ancestor and
monotonic lifetime charges, exercise a competing abusive peer, and explicitly
show bounded failure for work the512 policy cannot service. These models do not
claim whole-guest service bounds. Store tests pair v1/v2, reject semantic mismatch
without writes, cold reopen exact manifests and preserve owner bytes. Diagnostics
round-trip supported versions and refuse unknown values without changing layouts.

Full models, strict/fmt, original M3/Native3 regressions, fresh complete seven-mode
Kernel/Root image/stack/admission censuses and actual B/C downloaded production
must precede execution. Parent reviews the complete new source pin before actual
six-boot health/C-fault/offline-B-recovery and first-use qualification. Saved
Note/scalar data, remote floors, ordinary retirement and all genuine health
checks must pass again. Timeout or forced termination never counts as PASS.


## Consumer profile boundary correction

Structural support for healthversions1/2 does not widen historical Store consumers.
The original generic default briefly allowed a dirtyv2 journal to replay before a
later legacy resolver refused it. Actual same-byte models reproduced1write/flush
for selectedv2 BeginBoot and2writes/flushes for selectedv1 plus pending Stagev2.
No health promotion or owner-payload loss was observed, but pre-refusal mutation
violated the intended compatibility boundary. Those sources/raw failures remain.

Store now retains a private immutable two-case interpretation profile. Original
format/open/mutable-namespace APIs remainv1; only explicitly named downloadedv2
constructors opt into2. Profile checks precede format/publication and idempotent
receipts, cover every live selected/staged/KnownGood ref and checksum/base-bound
pending Stage, and retain all exact manifest/hash/admission guards. Unsupported
newest heads refuse without older-head fallback or repair. Wrong-profile cold
replay returns Unsupported; new incompatible publication returns InvalidRequest.

Actual V4 construction explicitly binds State's System profile after verified
network Packages; legacy State construction remainsv1 even in mixed-feature Host
models. Only System opens/formats/inspectors and M6 Host System observers opt in.
App Registry/scalar/Note/grant creation remains healthversion1; their payload
schemas and ABIs do not change. In particular the existing Note payload is already
format2/schema2, which is independent from its creation manifest's healthversion.
No profile is selected from media, an App scalar, a command or a renewed loan.

The final resource/adoption plan covers all seven actual relevant recipes:
ordinary Standalone/Managed/Recovery, owner Standalone/Managed/Recovery, and
negative. Models and independent public-API recovery tests precede those fresh
censuses; actual new-policy and legacy VM regressions remain separate gates.
