# Road to Evrosion 0.2

Prepared 2026-11-12. **Implementation started under the owner's explicit 0.2 goal.** The owner
has now reported running 0.1 with a positive visual impression; the
visual review record (local engineering archive) preserves that narrow scope.
Updated 2026-11-15: M6-01 through M6-08 now pass in the declared virtual scope.
Candidate14 completed actual signed B health/KnownGood, C failure/offline recovery,
two-Linux whole-target reproduction, the fresh graphical guide and a 652-second
engineering exercise with same-volume cold Saved reopening. The reviewed
204-file Main adoption also passes. M6-10 now passes bounded local VM engineering
acceptance with the recorded workspace checks and qualification limits. See readiness and
current progress. Physical M6-09 remains deferred;
public release and official signing remain separate owner decisions.

The working 0.2 target is **M6 VM-based Connected Developer Alpha**: an interactive
native session, one virtual network path and authenticated update retrieval with
real rollback. The [accepted owner amendment](plans/amendments/2026-11-12-m6-virtual-acceptance.md)
defers physical qualification to a later milestone; it does not waive any virtual gate. This implements
[E-025.69–77](plans/roadmap/E-025-initial-scope.md) and the existing
[post-0.1 direction](plans/release-project/Evrosion_R-007_to_R-011_Superfile_v1.md).
It refines the execution order without changing the foundational architecture.

Evrosion must become easier to use and configure while preserving the owner's
control and the computer's power. Each slice should make that visible: automatic
configuration of the supported network path, understandable status and errors,
useful offline operation, explicit authority and recovery that actually works.

## The experience we are building

Boot into a session that stays available for the owner to explore. Launch a
native application, edit and retain small test data, and grant or refuse file
access through comprehensible controls. The supported network device configures
itself, and a native diagnostic/download client explains connectivity and failures.
An app without network permission cannot use that path.

Fetch an authenticated healthy development generation B, show what will change,
stage it and activate at a safe boundary. Execute its actual downloaded code
after a cold boot and durably promote B to Known Good after genuine health.
Then a downloaded bad candidate C fails probation and returns to protected B,
with later user edits preserved and recovery available offline.
Qualify the declared QEMU virtual-machine profile. Physical execution is a later
qualification gate under the accepted owner amendment.

The first downloaded System cohort may retain the existing compatible Kernel,
protected Root and storage backend while replacing selected critical userspace
code. Its actual composition must be recorded. General Kernel/Root/boot-stack
replacement is a separate proof; it cannot be inferred from that demonstration.

## Execution order and completion gates

These are new execution-task identifiers. The referenced E/R/A identifiers are
the existing architecture requirements. M6-01 retains the owner’s positive visual smoke review. M6-02 through M6-08 now have current-source virtual PASS evidence; M6-10 now records scoped local VM engineering acceptance. Runtime completion requires each gate
below; design work or compilation alone is not a runtime PASS.

| Task | Deliverable | Completion gate | Dependencies |
|---|---|---|---|
| M6-01 | Owner review and 0.1 stabilization — PASS, visual smoke scope | Record what the owner understood, what was confusing and any failures; reproduce and triage findings. Retain the accepted 0.1 source/artifact identities. | Owner's next test |
| M6-02 | Interactive developer session | Session remains available until explicit exit; owner controls launch, file selection, refusal, crash/relaunch and saved test data without automatic keyboard stimuli. Renewable bounded CPU budgets retain cumulative accounting; legitimate use exceeds old proof-world/lifetime limits while an abusive app remains contained. Readable errors, focus, basic text/pointer input and clean retirement work. | M6-01 |
| M6-03 | Reproducible target artifacts and manageable evidence | Kernel, loader, admitted components and unsigned image match across cold/warm builds, different paths and two declared supported Linux environments with the same pinned inputs. Symbols remain correctly bound to artifacts. Evidence can be reconstructed from explicit immutable indexes without recursively embedding old reports. | Review; before update-candidate baseline |
| M6-04 | Device and resource safety | Select one virtual NIC after verifying its actual guest-memory DMA behavior. Prove scoped device access, bounded packet buffers, stop/reset/drain and safe retirement. Measure actor/stack/ABI/Job admission changes before expanding the graph. | Review and device feasibility |
| M6-05 | Time and entropy foundations | Define and implement bounded A-005/A-006 contracts: monotonic deadlines, wall-time/freshness confidence, adequate cryptographic entropy and explicit unavailable states. Exercise clock rollback, missing entropy and cold reopening of trust state. | Can run alongside M6-03/04; required before TLS/security claims |
| M6-06 | Native networking and one useful client | Actual guest NIC traffic supports the client's address configuration, DNS and bounded reliable transfer. A permitted native client shows a verified response; an unauthorized app or forbidden destination is denied. Offline, timeout and link-loss states are understandable. | M6-04; M6-05 before authenticated transport |
| M6-07 | Durable objects, verifier and executable admission | Persist actual acquired content, verify it under an independently provisioned development trust root, then parse/seal/map/admit an executable absent from compiled banks and execute it offline after a cold boot. Preserve compatible App/data namespaces and package-bound grant checks across builds. Offline bundles use the same verifier. | M6-03/05; can develop alongside networking |
| M6-08 | Network update and offline recovery | Retrieve through M6-06, verify/stage through M6-07, cold-execute healthy downloaded B and durably promote it after health; then downloaded bad C fails and offline cold recovery returns to B on the same owned disk. Preserve later edits and correctly revalidate permissions. | M6-06/07 and interactive controls |
| M6-09 | One physical reference machine — deferred by owner to a later milestone | On the nominated x86-64 UEFI target, prove boot, display, keyboard/mouse, storage and network through actual assigned devices. Use the target's actual memory map/reservations, bounded resources and physical outstanding-work stop/reset/quiescence proof. Start RAM/read-only, then use an explicitly authorized disposable test medium. Record controllers, firmware and recovery. | Inventory early; execute after virtual safety/runtime gates |
| M6-10 | Final 0.2 acceptance and handoff | Freeze the candidate, run the required current regressions and negative matrix, complete an actual interactive/network/download/rollback demonstration, test the guide in a fresh supported environment, and record local VM readiness with exact limits. | M6-01 through M6-08; M6-09 is explicitly deferred |

M6-03, M6-04 and the time/entropy design can proceed independently after review.
The common verifier can be tested with offline signed fixtures before networking
is ready. Physical target inventory should happen early, so actual controller
needs influence the device work instead of becoming a late surprise.

The owner explicitly deferred the physical gate from 0.2 on 2026-11-12. Complete
the virtual branch for this release; retain physical qualification as later work,
and never label QEMU or the read-only host inventory as physical Evrosion proof.
The nominated development PC remains protected by its host OS. No hardware
purchase, physical boot or personal-disk operation is assumed by this plan.

## Interactive runtime and usability

The 0.1 front door is a bounded scripted demonstration. A manual session requires
real lifecycle work: remove automatic stimuli from that mode, define sustained
service scheduling and shutdown, and keep the finite conformance profiles intact.
Do not obtain an interactive session merely by disabling watchdogs or removing
resource limits. Preserve operation deadlines, health probation, restart limits,
revocation/retirement and charged CPU/memory ownership. Record meaningful runtime
profile changes in an ADR and test them before adoption.

Current CPU charging consumes lifetime Job limits without replenishment. Define
renewable bounded execution budgets and their authority/window semantics while
retaining cumulative usage and ancestor accounting. Test a legitimate manual
session beyond the old world/Root/child limits and a competing abusive app;
neither counter resets nor an unlimited service budget can substitute for that
proof. The existing finite regression profiles retain their declared limits.

Use a small launcher, permission view, connection status and update/recovery view.
Keep underlying controls intelligible through keyboard focus, readable text and
basic pointer input. Build on the existing native contracts; full themes, window
management, a rich text system or a large application collection are not gates.
The network client may be a small native diagnostic tool rather than a browser.

## Device and network boundaries

The current reference device path provides scoped PIO. It does not implement
general PCI/MMIO/IRQ/DMA/IOMMU authority. Current device-free Root custody does
not prove device-bearing reconstruction. The NIC feasibility record must resolve
these facts before choosing its backend.

- A verified non-DMA reference NIC may reuse appropriate port mechanisms. Verify
  its behavior; a device's marketing name or an address check in its driver is
  not a containment witness.
- A guest-memory DMA device requires core-controlled mappings, buffer ownership
  and verified IOMMU or equivalent hardware confinement before claiming isolated
  DMA operation. Otherwise select the verified non-DMA branch. Stop/reset,
  device fencing and confirmed quiescence precede reuse or release. Extend the hardware capability mechanisms
  and interruption paths needed by that actual device. Do not substitute broad
  physical-memory authority or weaken isolation to get packets moving.
- Keep driver, network protocols, configuration and policy in userspace. Use
  versioned session/destination contracts with room for later adapters and address
  families. Start with the smallest protocols needed by the chosen client;
  automatic address configuration and resolution are part of the declared path.
- Use bounded shared Memory Objects/pools for packet payloads and small control
  messages. Keep backpressure and per-Job accounting explicit. The existing tiny
  control IPC and fixed actor graph cannot simply absorb unbounded packet work.
- Exercise real outstanding work during driver/service failure and cancellation.
  No stale delivery or premature buffer reuse; local apps/files and recovery
  remain usable. Reconnect when possible and report lost sessions honestly.

These preserve [E-006](plans/platform/E-006-driver-architecture.txt),
[E-011](plans/platform/E-011-networking-architecture.txt), the existing
[IPC discipline](designs/IPC_DISCIPLINE.md), [A-005/A-006](AUDIT_ACTIONS.md)
and [ADR-0042's device-bearing limit](adr/ADR-0042-scoped-userspace-pio-reference-backend.md).

## Authentication and update safety

Networking transports bytes; it grants neither release trust nor runtime
capabilities. Provision the development trust root independently of the server.
Development test keys remain distinguishable from official release authority.
Select reviewed crypto/TLS mechanisms through a documented implementation choice;
do not invent cryptography or disable certificate checks to make tests pass.

Separate monotonic operation time from trusted wall-time/freshness. Guest IRQ
counts are neither authenticated UTC nor cryptographic randomness. Unknown time
or insufficient entropy produces an explicit safe result. Installed software and
owner data remain usable offline even when new-update freshness cannot be proved.

The common verifier must reject forged or wrong signatures, wrong platform or
channel, bad size/hash, incomplete/mixed cohorts, unsupported contracts, obsolete
or inconsistent metadata replay, expired metadata and invalid root rotation.
Exact idempotent revalidation/resumption of the same still-authorized operation
is allowed only with its full identity and current trust/freshness checks.
Root succession must satisfy both old and new signature thresholds before durable
advancement through every required intermediate root. Persist trusted
metadata/version state and test interrupted writes. Remote replay floors and an authorized local KnownGood
boot are distinct: recovery must not silently reset security metadata. Resistance
to malicious whole-disk rollback requires its own witness and is not established
by ordinary Store counters.

Acquisition reserves bounded staging and rollback space before modifying state.
Partial content resumes safely or is discarded without altering the active
generation or formatting data. Download completion, verified staging, activation,
probation and KnownGood commit are separate states. Cold admission consumes the
actual persisted downloaded object; precompiled banks, host file replacement or
a progress marker alone cannot prove this gate.

Current process creation admits registered image objects. Add the bounded
persisted-image loader/admission path explicitly: validate ELF/contract bounds,
seal immutable content, map with existing W^X/guard rules, bind actual image
measurement and role/grant eligibility, and publish/start through the checked
lifecycle. Offline cold execution of valid content absent from compiled banks
and pre-execution refusal of malformed/incompatible content close M6-07.
Persistence and a valid signature alone do not close executable admission.

For this developer alpha, expose explicit Stage and Activate controls and protect
unsaved work. This initial test policy does not change the accepted responsibility
layers: eventual Layer 1 maintenance is automatic at safe opportunities, Layer 2
offers choices, and Layer 3 defaults to manual. Initial unchanged data schemas keep
rollback meaningful; any migration needs an independently verified reversible
path or a preserved compatible checkpoint before activation.

Follow [E-019](plans/platform/E-019-update-and-lifecycle.txt),
[R-003](plans/release-project/Evrosion_R-003_Official_Releases_Distribution_Updates_and_Release_Trust_v1.md)
and the existing [health contract](designs/BOOT_HEALTH.md). General Kernel/Root
replacement must independently prove its boot selection and recovery before
being advertised. Network-driver recovery does not close the common Root/Block
reconstruction gap recorded in 0.1 readiness.

## Physical target qualification

Choose for actual firmware/controller feasibility and available safe test media.
The existing custom ATA ports/geometry, five-key PS/2 input, 4 MiB Display aperture,
Q35 timer/interrupt assumptions and QEMU debug-exit are reference fixtures.
An ordinary 1080p framebuffer already exceeds that Display aperture. They are
not a ready-made generic PC profile.

Record discovery and capability assignment for the selected display, input,
storage, NIC and DMA/interrupt paths. Validate pitch/extent/mode and provide a
safe supported display mode. Prove an actually available diagnostics/recovery
channel rather than assuming COM1. Add only drivers needed by this target;
USB/xHCI, AHCI/NVMe and NIC needs must inform the common safety work.

Physical storage tests use a future explicitly nominated disposable medium, with
ownership and extent recorded before writes. Normal personal disks remain outside
that authority. An installer, partition migration, reclamation or host power-cut
experiment is not authorized by planning this target. Preservation-first consumer
installation remains a later binding product requirement.

## Required negative tests and final evidence

The final candidate must cover unauthorized/destination-forbidden networking,
malformed/truncated/oversized packets, queue saturation, bounded CPU/memory,
link loss, timeout/cancel, live service/driver failure and stale buffer/capability
refusal. Update tests cover hostile metadata/content, wrong trust roots, replay,
unknown time, missing entropy, storage exhaustion and interruption at each
published durable transition. A failed update must not block offline boot,
recovery or access to the compatible preserved owner data.

Run focused checks during implementation, then source-pinned complete regressions
at meaningful phase boundaries and final acceptance. Retain failed attempts
before repair, exact code/validation identities, actual images/signatures/packet
and disk evidence, negative outcomes and complete resource retirement. Compare
boot/image/RAM/IPC/App/response baselines with the accepted 0.1 methods, adding
network transfer/backpressure and update/recovery measurements. No arbitrary
performance competition is added.

The final record must distinguish VM execution versus deferred physical qualification, scripted
versus human interaction, development trust versus official signing, and actual
device recovery versus unproved general Root/boot-stack reconstruction. Document
real source/artifact hashes, dependencies and known limits. Public release still
requires the separate founder/source/signing/legal/security-intake decision.

## Optional work and future product scope

Remote developer diagnostics may follow the required path if useful. It needs
explicit enablement, target-scoped debug authority, authenticated peers and
encrypted transport under E-020.59. An unauthenticated or default public listener
is not a developer convenience. This optional tool does not block the core gate.

Wi-Fi/multipath, a full browser, accelerated GPUs, broad PC compatibility, full
SMP/consumer desktop, rich audio, AI, marketplace and Windows compatibility are
outside this 0.2 critical path. The original self-configuration, accessibility,
owner sovereignty, offline/privacy, bundled supported Windows compatibility and
preservation-first installation commitments remain binding for their later scope.

## Recorded 0.1 review and future walkthroughs

The initial owner visual smoke review is recorded above. For a deeper walkthrough,
start with the existing QEMU demonstration and explain its scripted behavior.
Observe boot/readability, launcher, selected-file access, refusal/cancel,
App/Shell crash and restoration, saved data and the separate System rollback
experiment. Record what the owner expected to control, confusing state and actual
failures separately from new feature requests. Do not describe this as an already
interactive daily desktop or try the fixture image on personal hardware.

Keep the reviewed candidate and evidence identifiable. A dirty tracked lockfile
remains a reported qualification limit; clean-revision checks require the accepted
clean validation snapshot. Do not rewrite a source snapshot merely to make a
check pass. Changes require appropriate qualification against the selected scope.
