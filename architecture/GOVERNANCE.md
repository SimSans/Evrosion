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
