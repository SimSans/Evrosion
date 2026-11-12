# Bounded durable store core

`ev-store` is a no_std/no_alloc userspace library for the first persistent machine
slice. It contains no device driver or kernel filesystem and grants no storage
access by itself. `SectorIo` belongs to an authorized storage-service backend;
ordinary applications must use capability-checked File/Object services, not raw
sector numbers or this volume-control interface.

The format is **Internal**, currently durable-record version **2**. Version1,
future versions and mixed root versions are refused without writes or automatic
migration; `format_new` still refuses every nonblank reserved sector. The
separately typed generation-manifest schema remains version1. Earlier immutable
v1 physical journal evidence stays v1 evidence; v2 needs its own actual path.
SHA-256 integrity fingerprints reuse the already
locked implementation. Checksums do not establish publisher authentication,
trusted generation selection or permission to access an object.

## Layout and protocol

The backend supplies at least 14 dedicated 512-byte sectors, or a separately scoped
offset region that does not touch earlier immutable block fixtures:

Exactly one live `Store` writer must own the entire physical region. The trusted
storage service must exclude independently opened or cloned backend aliases and
stop the old writer before reopening. Owning a backend value, borrowing one
`Store` mutably or leasing its shared transfer buffer does not establish this
volume exclusivity. The current physical fixture runs one Store/client/device
and reaps the old VM before the next opens the region.

| Relative sectors | Purpose |
|---|---|
|0–1|Alternating checksummed committed roots/high-water metadata|
|2–9|Eight operation-journal slots, reused only for completed history|
|10–11|Immutable generation-manifest slots|
|12–13|Separate mutable object COW slots|

Every record has canonical little-endian fields, version/kind, bounded lengths,
zero reserved bytes and a SHA-256 checksum. Root sequence and persistent
operation high-water never wrap. Reuse never resets either counter.

A mutation validates before writing, durably writes PREPARE, stages/verifies its
object and flushes it, then publishes the alternate root and flushes again.
A flush result must mean actual device durability, not cache acceptance. IO
failure poisons further use; the owned backend is recoverable through
`into_device`, and its driver must establish idle/reset before reopening.

Open verifies referenced content and completes one valid durable prepared
operation idempotently. A power cut can leave old or new committed state, never
partial published data. Reopening/recovery can itself be interrupted. Operation
IDs are persistent and volume-local, not runtime capability handles. Retained
IDs replay the same fingerprint/receipt without another write; conflicting input
rejects. Overwritten history returns StaleOperation and never reexecutes old IDs.
Eight slots bound history, not total operations. Tests exercise 19 complete
candidate-failure/A-reboot cycles and journal reuse beyond 170 operations.

`format_new` refuses any nonblank reserved sector and never silently erases an
existing volume. Partial initial provisioning fails closed and needs explicit
recovery/provisioning; it does not invent a valid KnownGood generation. Damaged
referenced records refuse access rather than reformatting owner data.

## Generations and health

A typed 192-byte `GenerationManifest` identifies a generation, coherent immutable
boot-critical cohort digest, exact supervisor-image digest, ABI fingerprint,
health-contract digest/version and critical checks. It references full matched
bundles; unchanged bytes may be shared. It is not an arbitrary data counter or an
ELF squeezed into a sector. The trusted lifecycle resolver must verify a complete
matching bundle before requesting activation, and actual executable admission
remains separate from persisting candidate selection.

Even initial A starts Pending, with `known_good() == None`. A boot attempt is
durably charged before a BootPlan is exposed. Admission reports bind that serial,
generation, process stamp, cohort/image/ABI and health contract/version. A different
process cannot overwrite an already recorded admission for that attempt. Health
reports must match it and provide named outcome/checks and the mutable-storage
probe; there is no `healthy: bool` shortcut. Only critical success establishes
KnownGood. Candidate failure/exhaustion selects protected A without changing
mutable object pointers or data. Failure without any KnownGood latches recovery.
KnownGood boots also have bounded consecutive attempts and fresh persistent
serials; a later A boot cannot reuse B's admission/health response.

Every committed root retains one durable **LAST failure** independently of the
eight-slot journal and the failed generation's reusable manifest slot. Its
112-byte capsule expands the root payload from272 to384 bytes (within416) and
keeps the failed generation, exact supervisor image hash, last charged boot
serial/attempt count, named reason, optional matched admission stamp and original
operation/sequence. Later successful health, mutable writes and journal reuse
preserve it; a newer accepted failure replaces it atomically with selection.
`last_failure()` reads this committed metadata without I/O and rejects poisoned
state. Initial provisioning has no capsule.

ProcessFault, MissingProgress and StorageFailure require the existing exact
matched admission and retain its nonzero stamp. AttemptBudgetExhausted is a
distinct reason: it captures the failed image/generation and last charged serial
before rollback or a new A boot charge. Bare pre-admission exhaustion has no
stamp; it never invents process execution or a fault. This is one last diagnostic
record, not an unlimited log or application authority.

The report fields are **an integration trust boundary**. The library checks their
binding but cannot prove the supplied process actually ran. The actual controller
must derive them from an admitted measured process/current attempt and real
fault/liveness/storage evidence. Host models construct observations explicitly;
those are not hardware boot-health proofs or application authorization.

## Validation and remaining work

Thirty-one model tests cover every read/write/flush interruption, torn sectors,
interruption during recovery, duplicate/conflicting/stale IDs, journal wrap,
initial probation, failed B→A, mutable-data retention, bounded boots, record corruption,
all sector single-bit mutations and 4096 arbitrary decoder inputs. Acknowledged corrupt writes are read back and rejected before any commit
receipt. Host and bare-metal lint pass. The model has separate volatile/durable storage.
Capsule cases add interrupted failure/replacement publication and recovery,
survival across24 unrelated commits and manifest-slot reuse, stale-report
refusal, optional truthful exhaustion stamps, corrupt canonical fields,
unsupported-version refusal and monotonic counter exhaustion. These remain
portable model evidence until actual v2 execution and disk reopening are proven.
`committed_boot_serial()` and `highest_generation()` expose persisted diagnostic
counters after health or rollback without I/O; poisoned state refuses both. They
let a read-only observer check actual durable attempts and manual generation
progress without treating the guest's completion report as storage evidence.

Actual M3 still requires the shared PIO backend, flush/cold-reopen interruption
proofs, complete trusted cohort resolution, distinct measured critical-service
A/B execution, real bound health/failure and actual automatic/manual A boot.
No hardware durability, authenticated boot, full filesystem or M3 acceptance
follows from these portable tests. The authoritative requirements are
[E-010](../../architecture/plans/platform/E-010-storage-and-filesystems.txt),
[E-012](../../architecture/plans/platform/E-012-boot-and-recovery.txt),
[E-019](../../architecture/plans/platform/E-019-update-and-lifecycle.txt) and
[E-025.34–44](../../architecture/plans/roadmap/E-025-initial-scope.md).

The additive `desktop` layout module keeps this durable format2 unchanged and
names three disjoint reference regions: System16..29, FileA32..45, FileB48..61.
Userspace endpoint policy translates scoped logical sectors; kernel filesystem
policy is not introduced. `require_blank` is a read-only preflight for explicit
fresh provisioning, never format-on-open-error recovery. See the separate
[desktop integration contract](../../services/block/DESKTOP_STORAGE.md) and
[current project status](../../docs/status/PROJECT_STATUS.md) for evidence scope beyond the
historical core-model assessment above. New full-desktop VM proofs remain pending.
