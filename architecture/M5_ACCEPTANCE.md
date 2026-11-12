# M5 / Evrosion 0.1 engineering acceptance

Status: **PASS — bounded Internal native architecture proof**, 2026-11-11.
The [readiness dossier](../docs/release/0.1-preview.md#validation-and-provenance) and
[formal record](../docs/release/0.1-preview.md#validation-and-provenance)
reconcile E-025.55–67 and R-011.18–28 with actual code, artifacts and executions.
M0 at `m0` and the original M1–M4 acceptances remain historical checkpoints.
Current lower-layer regressions preserve their accepted bounds.

| Canonical requirement | Accepted bounded behavior |
|---|---|
| E-025.56–58 | Source-built `.zion` contains immutable manifest, real AppIdentity, ELF/resources, contract/capability declarations and checked hashes; actual development installation/admission binds the matching package/image. |
| E-025.59 / A-003 | Real picker, held-key refusal, exact selected READ and denied replacement; explicit remembered policy/readback, fresh cold remint, actual quiescent inhibit/stop/reap/tombstone and cold refusal/cancel. Fixed local owner/session; general authentication/Trusted Control remains later. |
| E-025.60–62/.66 | Actual App/Shell fault words captured before reap, package/build/process/thread context, live Job/resource rows and read-only System inspection. Standalone unknown admission stays unknown; Managed generation identity comes from actual admission. |
| E-025.63 | Actual six-cold install/activate A, B replacement, A rollback, removal/reinstall and preserved B-written private data, with exact bank/process/authority retirement. |
| E-025.64–65 | Five actual RPCs to provider A, real A stop/reap and B binding, then five to B through unchanged consumer/SEND/endpoint. This is one test extension point, not a public extension ecosystem. |
| E-025.67 / R-011.19–23 | Real GTK/headless native App/picker/crash/restart flow and a five-cold continuing-disk System experiment: healthy Good/KnownGood, deliberately bad selected Shell/fresh missing-progress failure, protected Good return, independent Root+Block owner recovery and final usable App data. |
| R-011.21/.24 | Current M4 isolation/desktop, Native/owner/System/provider negative proofs, 389 Kernel tests, 157 targeted M5 tests and a source-pinned 103-check cumulative regression with 57 VM invocations. Expected-negative executions retain their actual failures. |
| R-011.26 | Frozen-source Ubuntu 24.04 VM build/run/GDB/reproduction commands pass; unchanged tests/architecture/inventory pass in a clean writable clone after preserving the extra read-only harness failure. Exact scope and cache reuse are recorded. |
| R-011.28 | Actual boot/App/response timing intervals, exact image/ELF sizes, conservative RAM bounds and five checked SDK RPC batches, with explicit clocks and measurement limits. |

The tested source fingerprint is
`b73186a8c6738e62ce0f7fc7e062615dd39926fcc2a58d84d29c54365fe6501b`.
All 495 current code inputs match the accepted execution cohorts. Full manifests,
actual artifact hashes, raw input/serial/disks/pixels and complete resource
retirement are retained in the linked immutable records. Final status/evidence
files are derived outputs and do not retrospectively change those manifests.

ADRs49–55 document the measured package/state, guarded Root stack/image capacity,
health/world profile and self-mailbox progress refinements. Their concrete
proofs preserve exact authority, current/next/KnownGood separation, uncertain
durable-operation ownership and original resource/health boundaries except the
explicitly scoped measured profile decisions. No foundational product promise
is superseded by this engineering acceptance.

The scope is controlled x86-64 UEFI/Q35/TCG, BSP userspace/parked AP, non-DMA
reference devices, fixed local ownership and Internal contracts. Actual App/Shell
restart and selected-generation recovery do not certify reconstructing the
common protected Root/Block after catastrophic device-bearing failure. Physical
host power loss, general SMP/DMA, production enrollment/Trusted Control and
model-only cold-attempt/in-flight-revocation cases are not physical claims here.

The local two-clean-build comparison passes. Cross-context binary identity is
unfinished: full embedded ELF metadata and loader diagnostic paths differ;
exact artifact hashes remain authoritative and EXC-0002 stays active. No
hermetic/production reproduction guarantee is added. The temporary loader and
Internal boot contract remain under EXC-0001.

This completes the local native 0.1 architecture proof. Official source commit,
signing/provenance, independent rebuild review, legal/contributor application,
verified private security intake, outreach and the founder's release decision
remain their separate public-release gates. The owner retains the GitHub push.
