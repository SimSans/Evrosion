# M4 graphical-machine engineering acceptance

Status: **PASS — bounded Internal reference-machine scope**, 2026-10-27.
The [formal M4 acceptance record](../docs/release/0.1-preview.md#validation-and-provenance)
reconciles the full desktop and refreshed original surface negative regression
against E-025.45–54/R-011.17 and bounded A-004 selected READ. Its current regression
matches all 360 compiled code inputs to the accepted desktop cohort; full
frontend checks pass 140 tests with one existing ignored test, and all 18
governance tests pass. [M3 acceptance](M3_ACCEPTANCE.md), M0 at `m0` and all
historical evidence remain unchanged. This is not M5/whole0.1 acceptance.

The [full desktop execution](../docs/release/0.1-preview.md#validation-and-provenance)
passes one actual fresh QEMU VM with source-built Root, Shell, Input, File, Block,
App and Display. Its retained kernel build input is
`c7bbafa08a3753f147a7cca3310824e34f12275c4278761b8784a0dd9da38df6`.
The record retains manifests, seven ELF images, actual Hello.zion/package and
catalogue binding, tested compiled source bytes, real input/control transcript,
serial/fault/lifecycle, raw disk snapshots and immutable results. Documentation
updates are not claimed to preserve a complete-tree build fingerprint forever.

| Required gate | Evidence and precise result |
|---|---|
| E-025.45–47 / R-011.17: software Display, compositor and App surfaces | Separate Display device authority and App/Shell RAM surfaces; actual protected Present reads only the matching blocked writer. Fixed 320×200 source surfaces, readable 280×116 App viewport and one-to-one logical sampling; no application framebuffer authority. Full desktop proof PASS. |
| E-025.48: one reliable input path | Actual bounded userspace PS/2 keyboard through authorized byte ports; QMP sends real make/break events. Held Enter cannot approve. One input path meets this gate; broad HID/USB or an additional mouse is not a prerequisite. PASS for this controlled path. |
| E-025.49–50: minimal shell/native app | Background, fixed window placement, launcher/status, focus changes, text, Open File and Crash Me in an actual isolated native Hello process. Source-built Hello.zion is admitted against the same six-role image/catalogue. PASS; package install/update lifecycle is separate M5 work. |
| E-025.52 / R-011.17 / A-004: trusted selected-file READ | Actual S5 Present/Input barrier, a held checkpoint lasting 68 running ticks with zero grants, fresh approval, Notes read, cancel preserving Notes, Private selection, and a new grant after App relaunch. Three actual selected-only SEND8 deliveries. [Approval annex](designs/PICKER_APPROVAL.md) defines the exact local-owner/READ-only scope and remaining Trusted Control boundary. PASS for bounded M4. |
| E-025.51/.54: App fault, shell/system survival and relaunch | Actual App PF14/error4 with retained fault/process/thread/address, stopped owner retirement, distinct replacement App, cleared RAM/no inherited File grant, actual re-grant/read. PASS. |
| E-017 shell/display separation beyond minimum exit | Actual Shell fault/replacement while Display and current App survive, new Input barrier and protected App Present restore the existing Notes content. Two actual faults/restarts overall; same Display process 2. PASS for injected App/Shell failures. |
| E-025.53: coherent resource/IPC/storage slice | 216 actual protected calls/replies, 9 actual admitted starts/incarnations, peak 7 live actors, 275 accounted private/shared RAM frames, returned mappings/metadata, independent cold File volume inspection and unchanged guard/System regions. PASS in this bounded graph. |
| Original component/negative regression on current code | [Current three-world regression](../docs/release/0.1-preview.md#validation-and-provenance) passes actual normal scanout, App absent-aperture PF14/error4 and Display RO-surface-write PF14/error7, 9 authority denials and exact retirement, with all 360 compiled code inputs matching the accepted desktop. The [first component proof](../docs/release/0.1-preview.md#validation-and-provenance) remains separate historical evidence. PASS. |

The graph retains 20 real captures. Fifteen required stages pass exact comparison
of all 1,024,000 pixels each; five transient mismatches remain explicitly failed
captures and are not relabeled successes. Three running held-key checkpoints
record 68/67/65 guest ticks. Actual input/QMP pause/capture/continue commands are
retained; host delay or paused guest time is not consent evidence. Small PNG
views of the [actual trusted picker](../docs/release/0.1-preview.md#validation-and-provenance)
and [actual selected-file app](../docs/release/0.1-preview.md#validation-and-provenance)
are lossless conversions, not replacement evidence.

[Current core/startup checks](../docs/release/0.1-preview.md#validation-and-provenance)
pass 355 kernel and 41 contract tests and strict host/target lint. The
[consent/readability correction](../docs/release/0.1-preview.md#validation-and-provenance)
retains 15 Desktop/Shell, 10 graphics and 138 frontend passing tests, one existing
ignored frontend test, exact source deltas and strict target checks. Earlier
[authority/reuse tests](../docs/release/0.1-preview.md#validation-and-provenance)
cover bounded pools/generation reuse, legacy-v1/Root-v2 separation and repeated
managed grant lifecycle. These are supporting model/component records; the
physical graph is the separate linked proof above.

The [submission/readability failure](../docs/release/0.1-preview.md#validation-and-provenance)
and [post-delivery rights-inspection failure](../docs/release/0.1-preview.md#validation-and-provenance)
remain immutable. Their fixes respectively prevent rearming consent during
Opening, preserve every font row, and let exact known rights masks reach actual
authorization; they do not widen selected App authority. Earlier stack, mapping,
serial-budget and post-grant failures remain linked from the working M4 progress
record. Successful execution does not erase these failures.

Accepted limits remain BSP userspace/parked AP, controlled Q35/TCG/OVMF with no
DMA, bounded software rendering, fixed owner/session and two source-defined
File objects. The App gets no raw ports, disk/volume authority, sibling object,
DERIVE, TRANSFER or File replacement method from a selected READ. Source Root
and the trusted Shell/Input/File are the explicit approval boundary. No
concurrent external File writer, mutable policy store, secure-attention route,
owner enrollment/authentication or broad privileged-control claim is made.
Source/portable coverage beyond the injected scenarios is identified as such.

Both File stores preserve data across the App/Shell failures and independent
cold opens. System sectors 16..29 stay reserved and untouched: GUI readiness does
not promote a System Generation to KnownGood. The actual full-graph health/
reboot/rollback composition, durable native app install/activate/replace/
rollback/remove, complete diagnostics/inspection, provider replacement and the
normal 0.1 `ev run` demonstration remain M5/0.1 engineering obligations. M3's
separate accepted persistence/recovery proofs are preserved, not automatically
rebranded as those future composed demonstrations. This record authorizes no
push, publication, public API stability or consumer-release claim.
