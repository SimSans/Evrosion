# M2 acceptance contract

Status: **PASS — verified 2026-10-27**, within the bounded Internal profile below.
[Final 71-check evidence](../docs/release/0.1-preview.md#validation-and-provenance) and
[readiness](../docs/release/0.1-preview.md#validation-and-provenance).

Scope is the union of [E-025.25–33](plans/roadmap/E-025-initial-scope.md),
[R-011.15](plans/release-project/Evrosion_R-007_to_R-011_Superfile_v1.md),
[A-001/A-012](AUDIT_ACTIONS.md), [Root custody §§7–15](designs/ROOT_AUTHORITY_CUSTODY.md)
and [IPC discipline §§18–25](designs/IPC_DISCIPLINE.md). The exact required failures
remain binding; historical status headers are not evidence of implementation.
Run `python3 tools/m2/binding.py` for the cumulative mechanism gate.

## Evidence boundaries

E71 means the [final 71-check acceptance](../docs/release/0.1-preview.md#validation-and-provenance):
262 kernel host tests, 150 matched recorded source hashes, complete boot snapshots,
repeated one/two-CPU execution, negative images and host/target/governance checks.
E68 is the preserved [68-check checkpoint](../docs/release/0.1-preview.md#validation-and-provenance).
E57 is the [eleven recovery cases](../docs/release/0.1-preview.md#validation-and-provenance).
All earlier behaviors below are rerun by E71; historical JSON remains unchanged.

## Capability-native userspace exit

| Governing requirement | Concrete proof |
|---|---|
| E-025.25–26: Root creates Jobs/processes, delegates, starts/routes/observes/restarts | E68 `supervisor_bootstrap`, `service_launch`, `service_restart`: separate source-built CPL3 Root and service images; exact grants and held admission |
| E-025.27–28/33: denial and attenuation; no ambient universal authority | Cumulative capability tests; actual READ success/WRITE and forged-handle denial; service images admit only measured role rights; Root/service control escalation is denied |
| E-025.29/33: capability transfer, timeouts and failure | E68 `capability_rpc`:8 waits, 6 deliveries, 4 returns, 2 queued refunds, 2 delivered no-refund failures; actual server faults before/after delivery |
| E-025.29: Memory Object sharing | Retained [M1 shared-memory hardware proof](../docs/release/0.1-preview.md#validation-and-provenance), rerun in E68; cap-RPC handle probes do not claim mapped-data access |
| E-025.30–31/33: typed userspace IPC and early IDL | Generated separate `ev.test.echo@1` and `ev.test.cap_echo@1` Rust client/server codecs, closed schemas, version/shape validation and actual executing callers/handlers |
| E-025.32–33: crash detection/restart and unrelated-service survival | E68 `service_restart`:64 victim faults/replacements, 128 healthy peer replies, 64 victim replies, 66 starts, stable Root and balanced backing/metadata |
| E-025.33: address-space isolation | Retained [M1 acceptance](M1_ACCEPTANCE.md), private measured executable roots, denied kernel/foreign access and final W^X/guard permissions in cumulative boots |
| R-011.15: Job hierarchy and custody/restart without authority leaks | Actual hierarchical admission/accounting, stable consumed CPU history, whole-graph revocation/reconstitution and generation-safe object/domain/thread/Job identities; E71 cumulative regression |

## A-001: Root custody failure matrix

| Required test | Accepted bounded proof |
|---|---|
| AF-007A: exactly one replacement ACTIVE | E68 `custodian_graph`:4 actual Root faults, 3 replacements, one current active token |
| AF-007B: no old descendant remains usable | Complete old graph stops/revokes; accepted escrow is invalidated; stale handles/tokens fail; physical and metadata baselines return before replacement |
| AF-007C: exact authority reconstruction | New canonical authority-set digest equals the manifest's **expected authority-set digest**, not the unrelated manifest-file hash |
| AF-007D: transfer versus Root death | Both serialized orderings: accepted transfer is subsequently revoked; post-revocation transfer rejects. The BSP ownership boundary gives a linearization point; parallel CPU/DMA racing is outside this profile |
| AF-007E: interrupted reconstruction cannot produce two active roots | E57/E68 admission, held-target, grant-preparation, image-load, activation and confirmation interruption worlds, plus late-capacity/failure-atomicity host cases |
| AF-007F: corrupted selection refuses activation | Actual bad manifest hash, bad image hash and separately measured wrong authority digest refuse activation/minting and enter independent recovery |
| AF-007G: exhausted budget enters recovery | Initial Root + 3 charged replacements in the finite 4096-tick profile; failed attempts remain charged, exhaustion stays latched and separately measured RecoveryReady executes |
| AF-007H: ordinary failure preserves Root/peers | E68 service restart proof above; this uses ordinary supervision, not catastrophic whole-graph reconstruction |

The same Authority/Scheduler/Registry/RPC/custodian owners survive replacement
within each world. Cleanup uses retained actual identities and image leases,
restored controller CR3 and stopped execution before reuse. A flag, balanced
counter or timeout alone is not a physical quiescence witness. The trusted runner
retains real failure records/tokens/reasons; userspace Ready cannot fabricate them.

## A-012: IPC discipline failure matrix

| Required test | Evidence and remaining condition |
|---|---|
| AF-IPC-001: generated call under NO_IPC_WAIT rejects | E71 verified: actual Mutex6 CONTROL acquisition/non-Copy guard and generated client; kernel rejects before a wait edge; explicit lease release |
| AF-IPC-002: A→B→C succeeds | E71 verified:3 actual processes; origin, trace, parent, depth, deadline and caller/callee identities are protected and checked |
| AF-IPC-003: ancestor callback rejects | E71 verified: actual C→A call returns cycle status without acceptance |
| AF-IPC-004: depth 9 rejects at maximum8 | E71 verified:9 actual threads across 3 processes, 8 existing request endpoints; no enlarged pools or ninth route |
| AF-IPC-005: descendant cannot extend deadline | E71 verified: B's deadline+1 rejects; forwarding reuses the actual protected deadline |
| AF-IPC-006: bounded queue/backpressure without growth | E68 real busy endpoint; actual Authority/Mailbox full-queue and capacity rollback tests preserve source ownership and bounded metadata |
| AF-IPC-007: timeout/retry does not duplicate the declared operation | E71 verifies explicit same-request READ_ONLY replay after preserving distinct-value late isolation. E68 already proves busy reservation, unique call/nonce, discarded late response and no duplicate handle/wakeup. See retry boundary below |
| AF-IPC-008: malformed length/cap count before effects | E68 total codec/schema and actual Authority shape preflight tests; actual malformed/forged/expired messages reject before moving the sender's cap |
| AF-IPC-009: receiver death obeys transactional ownership | E68 actual queued death returns one recovered handle; delivered death has no refund; old source handles stay denied. Revoked/pending escrow remains distinct in host pressure tests |
| AF-IPC-010: malformed decoding is total/atomic | E68 closed-generator negatives, all header bits/lengths, all 65536 rights masks and bounded arbitrary decoder/operation sequences; real transfer-failure paths preserve ownership before commit |

E71 also verifies exact receive/reply nonces, one wrong-thread rejection for a
shared-domain endpoint alias, six actual secondary-thread spawns, guarded measured
private stacks and final frame/metadata restoration. Only rank0 Exit0 completes
an actor world; other threads must stop under trusted cleanup before retirement.

Both current contracts are READ_ONLY. Explicit retry may execute the read again;
timeout is not proof of nonexecution and gives no delivered-cap refund. The
transport does not silently replay work or claim generic deduplication,
cross-crash exactly-once semantics or a durable mutation journal. Side-effecting
retry identities and durable operation IDs remain required by IPC §23 and
[E-008.16](plans/core/E-008-ipc-and-system-communication.txt) before such methods
are exposed, with durable execution implemented in M3.

## Deliberate initial limits and M3 handoff

Acceptance is Internal x86-64/QEMU, serialized BSP userspace with AP parked and
no delegated device/DMA authority. Static measured ELF, finite resource profiles,
bounded tables and generation-safe reuse prove mechanisms; they impose no
permanent Evrosion product VM/application-size limit. Trace IDs are boot-local;
production epoch/authenticated-generation selection is not established by trusted
source-built development bundles. RecoveryReady is independent code execution,
not persistent Known-Good selection, data preservation or a recovery UI.

M3 owns one virtual block path, E-010 object/file contracts, staging/journal/commit,
old-or-new recovery, immutable generations, health/Known-Good rollback and mutable
user-data preservation (E-025.34–44/R-011.16/A-014). M4 adds display/surfaces/input,
shell/native app/focus/scoped-file/crash survival. M5 adds `.zion`, AppIdentity,
picker/lifecycle/diagnostics/Job metrics, provider replacement and the recorded
end-to-end 0.1 demonstration. Neither a polished UI, broad hardware, networking,
self-hosting nor ordinary-user compatibility/migration gates block M2. They also
do not disappear from Evrosion's later product obligations.

M0 stays frozen at `m0`; historical JSON is unchanged. Local source-matched tests
are not an owner-branch commit, push, publication, independent-host reproduction or
Stable public ABI certification.
