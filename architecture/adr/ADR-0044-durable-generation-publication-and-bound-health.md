# ADR-0044 — Durable generation publication and bound health

Status: Accepted
Date: 2026-10-27
Owners: Project owner; storage and lifecycle maintainers
Related: ADR-0033, ADR-0039, ADR-0042, ADR-0043; E-010; E-012; E-019; E-025.34–44

## Decision

Implement the first durable generation mechanism in a safe no_std userspace
library, `ev-store`, over an explicitly authorized sector backend. Keep device
commands in the separate userspace block driver. This is an Internal volume
control mechanism; ordinary applications still require scoped File/Object
handles. A successful storage model or isolated generation fixture does not
complete that service interface or the entire M3 milestone.

One physical region has exactly one live Store writer. Backend ownership or a
shared transfer-buffer lease alone cannot exclude a second independently opened
backend alias. The trusted service must enforce region exclusivity and stop the
old writer before reopening. The current VM runner retains one device and reaps
each old VM before starting the next.

## Durable publication and retry

Use fourteen dedicated 512-byte sectors: two alternating committed roots, eight
reusable journal slots, two immutable generation-manifest slots and two mutable
object COW slots. Records carry canonical fields, lengths, reserved zeros and
SHA-256 checksums. Checksums provide integrity, not publisher authentication.

Each mutation durably prepares its persistent operation ID, stages its new
content and publishes an alternate root, with flush and readback at each
boundary. Referenced content must match before a receipt is returned. Failed
I/O poisons further use until the backend is recovered. An error after a commit
flush may already have executed: retry the original persistent ID after reopen,
never infer nonexecution or substitute a fresh ID.

Recovery can complete a durable prepared operation and may itself be interrupted.
Retained operation IDs replay only identical fingerprints and receipts without
another mutation. Reused journal history yields StaleOperation for old IDs.
Root sequence, highest generation and boot serial are monotonic and never wrap.
Formatting refuses nonblank reserved sectors; corrupt committed content fails
closed rather than erasing owner data.

Durable record format v2 adds a 112-byte LAST-failure capsule to the committed
root. A failure receipt in the eight-entry journal could disappear on reuse,
including a later torn prepare. The capsule retains failed generation, image,
attempt/serial, named reason, optional actual admission stamp and original
operation/sequence independently of both journal and manifest-slot reuse. Root
payload grows from 272 to 384 bytes within the existing 416-byte bound. Version1,
future versions and mixed versions are refused without writes or automatic
migration. Earlier immutable v1 evidence remains evidence for its original
format and must not be relabeled as v2 execution.

## Coherent selection and actual health

A generation manifest binds a complete immutable boot-critical cohort, exact
critical image, ABI and health contract. A read-only development catalogue binds
the actual kernel input identity, controller, driver, A/B images and contracts;
the measured kernel independently checks the retained component hashes before
publishing it. The catalogue avoids a circular kernel-binary/self hash. This
trusted development bundle is not production authenticated boot.

Even initial A begins Pending. Charge a durable attempt before exposing its
BootPlan. Associate the attempt with the actual admitted process/thread and
image. Generic Ready means startup, while CriticalReady means the named critical
checks finished. Before granting KnownGood, the userspace lifecycle controller
requires authenticated current service events, a durable mutable-object probe
and a fresh liveness observation after that probe. There is no caller-supplied
healthy boolean. A real typed fault records the failed attempt and atomically
selects protected KnownGood without changing mutable object data.

A live critical service can also fail initialization without faulting. Anchor
one 64-tick initialization window at the first actual LIVE observation; polling
and incoming startup events cannot reset or extend it. CriticalReady must arrive
before that absolute deadline. Expiry while the actual service remains live
commits a matched MissingProgress health outcome, selects protected KnownGood,
then ordinarily stops/reaps that service. It does not manufacture an exception
or kernel Fault Record. Both failure outcomes retain the real admitted image,
attempt and process stamp; only successful critical health performs the durable
same-data probe and can establish KnownGood.

Authenticated event receipt carries sender process/thread identities derived
from the actual running scheduler caller. A bounded side table follows the
exact accepted mailbox ticket. Missing or stale provenance refuses before
dequeue; user payload integers never authorize health. Ordinary capability
checks scope create/start/stop/identity/observe/reap and event operations.

The trusted lifecycle controller needs the existing registry's complete branch
rights (DERIVE, TRANSFER and REVOKE) on the two exact objects it delegates. Its
shared-memory source is READ/WRITE/MAP plus those rights (231); its event-send
source is SEND plus those rights (232). Critical children receive only READ and
SEND respectively. Omitting REVOKE would make the ordinary registry delegation
fail; this corrects the producer's attenuation rather than weakening registry
checks or giving ordinary applications volume/controller authority.

The initial physical proof uses actual source-built critical A/B processes:
healthy A finishes its checks and remains live; B faults through a forbidden
write before CriticalReady. The controller rejects its own forged readiness
events both before and after starting the service. Cold automatic and manual
rollback must actually run A again, preserve B's last-failure capsule and keep
the changed mutable data. A final read-only boot must leave every disk byte
unchanged.

The separate [missing-progress execution](../../docs/release/0.1-preview.md#validation-and-provenance)
is PASS across five fresh VMs using one retained kernel/catalogue and a distinct
measured silent B image. B emits generic Ready, remains alive without
CriticalReady, and is observed live from tick1628 through1710 before its ordinary
stop at1880. The observed82 ticks exceed the original64-tick window; no fault is
reported. Userspace durably records reason2/MissingProgress with the exact actual
admission stamp. Cold automatic and manual execution run healthy A again. The
LAST capsule, exact original Health receipt and owner-data-B survive journal and
manifest-slot reuse; final Verify changes no disk byte and read-only observers
attempt no mutation. ProcessFault remains a different measured profile/reason1;
the runners reject relabeling one outcome as the other.

Generation execution has its own finite 2048-tick/2048-CPU-per-actor development
profile, while the earlier block and journal profiles retain 1024. The parent
keeps its 4096 aggregate CPU budget, and the transition bound stays 100000. This
is justified by the preserved [first deadline failure](../../docs/release/0.1-preview.md#validation-and-provenance)
and [diagnostic execution](../../docs/release/0.1-preview.md#validation-and-provenance):
manual recovery was actively publishing call91 with 26 completed mutations;
the previous reply was eight ticks before the inherited stop. The driver alone
had consumed 799 CPU ticks. A larger elapsed bound without adequate child CPU
charges would merely move the failure. The current proof must report actual
elapsed ticks, each child's consumed CPU, matching parent total, transitions and
reservation high-water. No clock, ancestor usage or consumed budget is reset.

## Verification and remaining obligations

Model tests cover torn writes, every I/O interruption, interrupted recovery,
corruption after acknowledged writes, retained/conflicting/stale IDs, journal
reuse, monotonic exhaustion, probation, matching admission and durable failure
retention. Physical acceptance additionally requires the current-format
fifteen-VM interruption suite and five-VM A/B suite, independent read-only disk
inspection, exact component measurements and complete resource retirement.
See [M3 progress](../../docs/release/0.1-preview.md#validation-and-provenance) for executed evidence.

MissingProgress uses the same 2048-tick/per-actor CPU profile and 100000-transition
bound, with matching actual child/ancestor accounting. Phase elapsed totals are
977/1222/966/1231/230 ticks; peak transitions71279 and peak pending1 remain bounded.
Completed mutations remain23/28/18/32/0. This proves actual missing readiness,
ordinary live stop and cold rollback, not cold boot-attempt exhaustion. Three
charged attempts, exhaustion fallback and recovery-only latching remain model
coverage until a separate physical exhaustion path is executed. A-014's initial
Started/probation/KnownGood contract and whole-M3 acceptance remain pending the
owner-recovery and combined current-source gates.

Fresh-VM reopens test guest restart; they do not prove host physical power-loss
behavior. The finite shared-buffer transport excludes admitted cancellation as
described in ADR-0043. [ADR-0045](ADR-0045-scoped-file-object-service.md) records the
accepted scoped File/Object subset. Owner-operated separately executable
recovery and the cumulative M3 gate remain obligations; broader live
device-bearing recovery also needs its own device-lifetime proof.
Separately executable recovery here means that its trusted
controller works independently of the failed normal service, desktop and
network; E-025 does not require an additional recovery program. This decision
changes mechanisms within the owner's
engineering mandate and preserves the original system guarantees.
