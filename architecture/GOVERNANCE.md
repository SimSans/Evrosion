# Engineering governance

Architecture states the intended guarantees and component boundaries. Running
behavior does not silently rewrite them. When code and architecture differ,
either fix the code, record a justified ADR or approve a narrow expiring exception.

| Decision | Review requirement |
|---|---|
| Routine implementation detail | Focused engineering review and appropriate tests |
| Significant mechanism refinement | Evidence, compatibility/risk analysis and an ADR where required; preserve the existing guarantees |
| Contract or foundational guarantee | Explicit decision through the applicable architecture process; compatibility tests and founder approval where required |

No temporary shortcut becomes precedent merely because it executes successfully.
Foundational changes are proposals until accepted; routine work need not restart
settled architecture planning.

## Continuous refinement at every development milestone

Starting with the active M8 / 0.4 work, each 0.X milestone includes incremental
refinement during implementation **and a documented refinement review before
engineering sign-off**. This is a process check alongside that milestone's
existing functional acceptance gates; it does not retroactively change earlier
accepted checkpoints or imply that the current source has passed them.
Do not accumulate all cleanup for 0.5 or 1.0.

The closeout review must record, against the exact candidate and its supported
profiles:

1. **Simplicity and maintainability:** assess oversized responsibilities,
   duplicated/dead mechanisms, avoidable abstraction, legacy scaffolding and
   build/test infrastructure. Prefer one canonical mechanism per concern under
   E-026.37–44. Reduce complexity rather than merely counting lines.
2. **Security, correctness and recovery:** preserve capability isolation,
   bounded resources, exact authority and original operation identities,
   data preservation, Known Good and rollback. Repeat affected positive,
   negative, compatibility and interruption tests after behavior-changing edits.
3. **Measured efficiency:** compare like-for-like boot/response latency,
   image size, memory, CPU/IPC/resource usage and unnecessary always-on work
   where measurable. State fixture, toolchain, source/artifact identities,
   method, uncertainty and missing baselines; never invent improvements.
4. **Owner experience:** check actual supported task flows, understandable
   errors, accessibility/focus and recovery paths. Distinguish machine
   observations from human usability acceptance.
5. **Decisions and follow-up:** record what was simplified, what was deliberately
   retained, results, regressions and remaining debt. Assign bounded follow-up
   work with rationale; issues violating a required gate or invariant block
   sign-off rather than becoming an undocumented waiver.

Prefer small, reviewable, behavior-preserving refactors and regression checks.
Do not remove security checks, compatibility fixtures, historical evidence or
runtime guarantees solely to shorten source. New shared abstractions must reduce
actual duplication without weakening authority boundaries. Substantial mechanism
or contract changes still require the established ADR, compatibility and founder
decision process. No unrun test or historical PASS transfers to changed bytes.

M8's existing M8-12 resource/response checks and M8-14 integration closeout
are the first opportunity to attach this refinement record. Larger optional
consolidation at 0.5 and production hardening toward 1.0 remain additional
work, **not substitutes** for per-milestone refinement. Distribution, official
signing and consumer-installation decisions retain their separate release gates.

## Contract maturity

- **Internal:** no external compatibility promise.
- **Preview:** deliberately exposed for testing; changes need migration notes.
- **Stable:** compatibility is promised and enforced by automated tests.
- **Deprecated:** compatibility remains during the declared transition window.
- **Removed:** allowed only after that window and its required migration work.

Nothing becomes Stable merely because the product has a version number. Keep
[invariants](INVARIANTS.md), [ADRs](adr/README.md) and the
[exception register](exceptions/REGISTER.md) consistent with the implementation.

## Evidence

Record exact source and artifact identities, commands, outcomes and limits.
Distinguish a design, compiled code, model tests, actual guest execution and human
acceptance. Preserve failed attempts alongside later successful runs. Do not
rewrite immutable records to transfer a PASS to different inputs.

Public technical editions are identified by their actual content hashes and
edition metadata in the [source map](plans/source-map.json). They must not claim
to be unchanged imports when edited. References should resolve to published
technical material; version-control history is not a substitute for a usable
current document map.

The source publication decision and an official signed image release are separate
from local engineering acceptance. License application, contributor rights,
private security reporting and release authority have their own readiness checks.
