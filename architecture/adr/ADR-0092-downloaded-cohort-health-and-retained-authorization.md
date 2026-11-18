# ADR-0092 — Downloaded cohort health and retained authorization

Status: Accepted Level B implementation refinement; private component tests pass. Integrated resource admission, genuine guest health and C-to-B recovery remain pending.

## Problem

The current downloaded-B guest proves acquisition, explicit App activation and
offline cold execution. Those facts do not establish System health or protected
Known Good. A later candidate also replaces the current release metadata: keeping
an older package digest alone does not preserve its publisher's authorization.
Cold recovery must independently verify the retained member, rather than infer
its authenticity from the newer candidate's signatures.

The existing System Store already supplies transactional selection, BeginBoot,
attempt charging, Admission, probation, health and recovery. A parallel update
health journal would introduce conflicting authority and unnecessary recovery
states. Extend the existing mechanism with an exact downloaded cohort instead.

## Decision

The initial V4 System cohort records the actual compatible Kernel input,
protected Root, Shell, Input, File, Block, Display and authenticated downloaded
required subject. Its recipe binds the actual component measurements, package
and executable identity, V4/App contracts and health contract. Existing explicit
catalogue mode masks allow selection and recovery modes to name the same cohort;
actual Admission separately binds the current bootstrap and process identities.
The NIC is optional for offline health and recovery. This cohort does not replace
the Kernel, Root, boot stack or storage backend.

Standalone owner operations can initialize and select a coherent downloaded
cohort. Managed boot must durably charge BeginBoot before starting its Shell and
downloaded subject, then commit Admission from actual Root/subject identities.
Ordinary warm App activation remains a separate developer operation and earns
no System health. Recovery starts the protected Root and Block path without
launching the normal session or fetching content; explicit Known Good selection
prepares a subsequent managed boot.

Probation retains the seven actual admitted identities even when a subject
faults before its first successful LIVE observation. The first fresh actual Root
LIVE after durable Admission anchors the progress window; no child LIVE is
invented. Success requires actual startup for all seven members. Only Root,
Shell and the downloaded subject have the genuine
CriticalReady contract; never fabricate critical events for the other services.
Their authenticated progress must meet one anchored 64-tick deadline. A durable
System-only write/flush/readback probe and fresh observations of all seven actual
members precede success. Probe and publication continue within the original
bounded operation cut; neither renews the progress window. Generic Ready,
successful registration, a drawn frame and owner selection cannot promote health.
The downloaded Hello subject emits critical progress only after its startup,
grant, initial protected-data read and actual presentation checks succeed.

The session's existing data is readable during probation. Mutating operations
remain refused until genuine health succeeds, so an unproven candidate cannot
alter the protected user's data. Later successful edits belong to the separate
mutable namespace and survive a subsequent rollback.

System Health(CriticalPassed) must commit first. A compact local HealthReceipt
then binds the actual System Known Good manifest, current Registry record and
exact backend/loan to acquisition's active member. The canonical acquisition
Commit records that same member as Known Good before releasing the probation
write fence. It changes neither remote replay floors nor remote metadata. These
are two ordered publications, not an atomic cross-namespace transaction. Cold
opening repairs an interrupted System-ACK/acquisition-ACK gap from the actual
System manifest, current Registry and authenticated retained member before a new
candidate may replace their only remaining content reference.

## Retained publisher evidence

The private acquisition checkpoint becomes explicit `EVACQ002`/version 2. Each
candidate, active and Known Good member retains references to its exact signed
root and Targets objects. Three proof pairs add 336 bytes inside the existing
4 KiB checkpoint; they do not create a second trusted Snapshot. Existing content
and live-member interfaces retain their sizes.

Cold opening verifies each retained proof against the authenticated root
succession chain, checks the old Targets signatures and complete target
association, and rehashes the actual stored content. An old local B may remain
usable below C's current replay floors. It cannot claim a future role version or
an inconsistent equal-version identity. Reopening previously accepted local
content requires no network clock and does not reapply current remote expiry;
accepting new remote content still requires the full current verifier and fresh
qualified time. Local recovery never resets security floors.

Version 1 is refused explicitly. There is no implicit migration, reformat or
conversion of unproven retained members. Existing experimental disks remain
preserved; new qualification uses an explicitly owned new VM test disk. This
changes an unreleased M6 experimental checkpoint, not published 0.1 owner-data
formats. The root of local selection/health remains the protected Root and its
durable media; this does not establish tamper-resistant health history or
resistance to malicious whole-disk rollback.

## Failure and owner preservation

A fault in the downloaded subject is a critical-component fault, distinct from
a Root ProcessFault. Preserve its actual PID/TID, image, admission, generation,
serial, attempt and kernel fault facts. Vector zero and a zero instruction
pointer are valid faults. The capture tick records observation, because the
current kernel observation API does not supply the exception's occurrence tick.

Before publishing its hash reference through the existing System journal, write,
flush and fully read back a bounded immutable 256-byte fault summary in the
content namespace. It is a summary, not the full register archive. An interrupted
publication can leave an unused reserved object; it cannot publish an unverified
reference. Existing journal roots retain their wire encoding unless the new
failure-evidence extension is present; older readers refuse that extension.
Do not promise immediate durable logging through a failed Block actor. Retain
uncertain ownership/fences and follow bounded later-boot recovery instead.

The V4 Root controller uses the established private, one-claim resident Slot
pattern, as its Update and Controller already do. Its retained fields occupy
charged BSS instead of a large automatic run frame. Initialization must preserve
the actual immutable bootstrap mapping lifetime, expose one mutable owner, and
retain ordinary explicit actor retirement on terminal paths. This introduces no
heap, self-reference, additional capability or stack increase. The private
component census measures the resulting image/BSS and resolved stack; the
capacity profile and complete selected Kernel still require separate admission.

Continue content operations through the existing single affine Backend and
resident continuations. Foreign owners, stale loans, changed heads, unresolved
I/O and stale process identities refuse. No retry of accepted I/O, invented
success, larger deadline or automatic formatting may substitute for recovery.

## Alternatives and compatibility

Keeping only the old package hash loses publisher association after C replaces
B's metadata. Requiring old B to equal current remote floors prevents useful
offline rollback. Treating signature/GUI readiness as health bypasses actual
probation. Duplicating System policy in acquisition creates two competing boot
authorities. The chosen mechanism preserves the existing separation between
remote authorization, local selection, health and mutable user data.

This refinement implements the existing [boot-health contract](../designs/BOOT_HEALTH.md),
[M6 gates](../M6_PLAN.md) and [durable-selection mechanism](ADR-0090-durable-local-update-selection.md).
It adds no capability, automatic elevation, network requirement for local boot,
physical qualification, general Root/Block reconstruction or release authority.
Resource limits require their own measurements and declared profile changes.

## Evidence and outstanding acceptance

Private signed-Store composition tests cover older B under current C metadata,
missing/corrupt/wrong retained proofs, explicit v1 refusal, exact active/Known
Good associations, genuine System health receipts, child-fault evidence and
later Note/replay-floor preservation through modeled rollback. Store tests cover
journal interruption and failure-evidence refusal. These are component/model
proofs, not actual guest health or recovery.

Before joining Main, require source-pinned component and strict checks,
independent review, and passing actual Root/Kernel resource censuses. Then prove
actual B probation and durable Known Good, later nonempty edits, real downloaded
C fault, and same-owned-disk offline cold recovery to B with correct permissions,
unchanged security floors and complete actor/frame retirement. Keep current B's
already-passing download/cold gate distinct until these additional gates pass.
