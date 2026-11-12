# Contributing

Start with the [quickstart](docs/development/QUICKSTART.md),
[preview limits](docs/release/0.1-preview.md) and
[technical architecture](architecture/README.md). Evrosion aims to make computing
easier while preserving owner control, recovery and the machine's power.

Bug reports, reproducible tests, documentation corrections and focused technical
feedback are useful. Describe the expected behavior, what happened, the exact
source/build identity and a minimal reproduction using disposable data.
Report security issues through [SECURITY.md](SECURITY.md), not a public exploit report.

## Reviewable changes

- Explain the concrete problem and resulting behavior.
- Keep changes focused and identify affected contracts, invariants or ADRs.
- Understand the submitted code, verify its provenance and preserve required
  third-party notices. Do not submit credentials or private diagnostic archives.
- Run appropriate checks and distinguish executed results from assumptions.
  Compilation alone does not prove a guest, device or recovery test passed.
- Preserve original failures and their inputs. A later success does not justify
  editing an earlier result into a PASS.

Useful checks are listed in the [quickstart](docs/development/QUICKSTART.md).
Changes to bare-metal or feature-specific paths need their relevant target checks
and actual workflows; workspace defaults are only a subset.

Implementation improvements are welcome. Significant mechanism changes need
evidence, tests and an ADR where required. Contract changes need compatibility
analysis. Foundational guarantees follow the [governance](architecture/GOVERNANCE.md)
decision process; implementation does not silently replace them.

## Contribution-rights status

The founder has applied the first-party license split described in
[LICENSE_POLICY.md](LICENSE_POLICY.md); third-party terms remain intact.
Substantial external code
contributions are temporarily not mergeable until the required contributor
agreement and provenance process are active. Feedback and review do not require
inventing a new agreement here. No copyright assignment, commercial license,
CLA, ECA or DCO contract is created by this guide.
