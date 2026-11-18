# Project status

Updated November 18, 2026.

| Checkpoint | Engineering status |
| --- | --- |
| 0.1 | Published developer source preview; preserved at `v0.1.0`. |
| 0.2 | Historical bounded connected-alpha VM acceptance, followed by stabilization. Physical qualification was deferred explicitly. |
| 0.3 | Historical bounded offline document-workflow VM acceptance, including saved-data reopening and failed update recovery. Human usability acceptance remains pending. |
| 0.4 | Implementation and component qualification in progress. All fourteen full acceptance gates remain open. |

This source update includes work since the published 0.1 preview. Historical engineering results apply to their recorded inputs. The exported source has publication edits and requires its own validation; it is not an official signed image release.

Current 0.4 components include larger documents, multiple editors, Files namespace operations, Inspector, scoped reader controls, local development package installation and private application data. Bounded observations cover save cancellation, full-volume refusal, stale-writer conflict, cold reopening, namespace operations, checked shutdown/restart and an independent recovery boot after Root loss. These are component results with separate source identities, not a complete integrated acceptance.

Protected permanent removal and higher-generation object reuse remain unverified at runtime. One attempt reached Trash and protected Cancel with the owned volume unchanged; the latest stopped before the removal picker. Pending code and diagnostic deltas are retained under [experimental source](../../development/experimental/README.md).

Remaining work includes combined-candidate qualification, interruption/recovery boundaries, protected accessibility and layer controls, normal-Shell health, clean offline reproduction, resource/response measurements and the required thirty-minute session. See [0.4 gate progress](M8_PROGRESS.md) and the [M8 plan](../../architecture/M8_PLAN.md).
