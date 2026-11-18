# Accepted 0.2 stabilization and alignment work

Authorized by the owner on 2026-11-15 after bounded local VM acceptance of M6.
This is follow-up engineering, not a reopening of the accepted virtual gates or
authorization for a public release, physical boot, or personal-disk operation.
The M6 readiness record retains its exact source identity and qualification
limits in the local engineering archive. Changed code needs its own validation.

## Direction and authority

Apply the original F/U requirements, E/R decisions, explicit supersessions
and [governance](GOVERNANCE.md). Derived summaries do not replace these sources.
Preserve owner sovereignty without ambient process elevation; userspace policy
and drivers; bounded capability/IPC/Job mechanisms; local/offline operation;
separate immutable code and durable data; health-gated Known Good and independent
recovery; accessibility; native independence; and the deferred consumer migration
and bundled Windows-compatibility requirements. This plan changes no foundation.

## Work and completion evidence

| Task | Work | Completion condition |
|---|---|---|
| M6-S01 | Reconcile architecture and implementation status | Inventory canonical sources and supersessions; trace important guarantees to implementation/evidence; correct stale summaries and identify actual unresolved conflicts without rewriting historical evidence. |
| M6-S02 | Investigate IPC performance | Preserve the accepted 0.1/0.2 measurements; compare current workloads under declared, controlled conditions; isolate supported causes where possible; measure any change without reducing checks or claiming physical latency. |
| M6-S03 | Improve stack headroom | Inspect linked stack chains, remove unnecessary overlapping stack storage where justified, retain the existing guarded stack sizes and admission limits, and measure all affected profiles. Keep recursion/indirect/interrupt limitations explicit. |
| M6-S04 | Validate the stabilization candidate | Pin exact changed source and artifacts; run appropriate host, linked-resource and actual VM regressions, including persisted data, signed update/recovery and relevant failure paths. Preserve the accepted snapshot and all failed attempts. |
| M6-S05 | Prepare owner walkthrough and 0.3 proposal | Provide a usable local walkthrough and an explicitly proposed, bounded next milestone. An engineering exercise cannot be recorded as new human acceptance. |
| M6-S06 | Reconcile final implementation status | Update the implementation summary; bind actual results, limitations and retained preimages in the final report. |

Use isolated experimental checkouts and retain changed-file preimages. Changes
to foundational guarantees remain outside this scope. Any experimental
optimization that fails validation stays outside the accepted implementation.

## Validation approach

Compare identical benchmark fixtures and declared QEMU/compiler settings rather
than interpreting unrelated historical timings as a causal experiment. Run
performance VMs serially, retain every sample and explain host-load uncertainty.
Inspect actual linked code for stack changes; a fixed-reference census is not a
formal whole-program bound or a runtime high-water measurement. Use existing
functional and negative tests to protect ownership, refusal and recovery behavior.

Documentation changes require architecture, link and source-integrity checks
and review of implementation status. Never mark a source reviewed merely to
clear a warning. Historical readiness proofs retain their original scope.
Summaries distinguish current records from older checkpoints.

## Focused 0.3 proposal — not an implementation commitment

Proposed outcome: one useful native local document workflow that an owner can
understand without studying the component graph. Select/open an explicitly
authorized document, edit bounded text, save with an honest durable result,
close/relaunch and recover it after reboot or a failed application update.

Proposed gates:

1. Define bounded file selection/navigation and an IDL-defined, language-neutral
   text/focus/semantic-state contract, with checked bindings, before extending
   the GUI. Preserve exact-object
   grants; navigation must not silently grant a surrounding directory.
2. Provide keyboard operation, visible focus, readable labels/status/errors and
   semantic accessibility information. State which accessibility providers and
   input methods are actually implemented; do not call keyboard support a full
   accessibility implementation.
3. Replace the tiny demonstration note only through an explicit compatible
   data-schema plan, preserving existing saved data and a proven rollback path.
   Keep immutable package identity, writable data and live capabilities distinct.
4. Prove offline open/edit/save/reopen, app crash/relaunch, denial/cancel, storage
   exhaustion/interruption and failed-update recovery with the same owner data.
5. Measure resource/stack/IPC/response costs before admitting a larger graph.
   Preserve the native path without mandatory AI, foreign runtime or account.

Before selecting that milestone, retain the stabilization findings and obtain
the owner's real usability feedback. Consider E-014 build-platform evolution and
the existing common Root/Block recovery gap explicitly rather than silently
assuming they are solved. Physical qualification needs its own selected target
and safe-media authority. General Kernel/Root updates, broad browser/HTTPS,
Windows runtime implementation, consumer installation and public release are
separate scopes; the underlying product promises remain binding.
Early public project material continues to use GitHub under R-005; this proposal
does not select a new website or community infrastructure project.
