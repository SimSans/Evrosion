# Architecture source index

This public technical edition preserves the architecture's document IDs,
requirements, contracts and decision rationale. Edited editions have new content
hashes and declared edition metadata in [plans/source-map.json](plans/source-map.json);
they are not described as unchanged imports. A plan does not prove execution.

## Technical entry points

- [Overview](README.md), [governance](GOVERNANCE.md), [invariants](INVARIANTS.md)
  and [glossary](glossary.md).
- [Accepted ADRs](adr/README.md), [exceptions](exceptions/REGISTER.md),
  [audit actions](AUDIT_ACTIONS.md) and [maturity declarations](status.toml).
- [Root custody](designs/ROOT_AUTHORITY_CUSTODY.md),
  [IPC discipline](designs/IPC_DISCIPLINE.md),
  [selected-file approval](designs/PICKER_APPROVAL.md),
  [boot health](designs/BOOT_HEALTH.md) and
  [identity taxonomy](designs/IDENTITY_TAXONOMY.md).
- [M1](M1_ACCEPTANCE.md), [M2](M2_ACCEPTANCE.md), [M3](M3_ACCEPTANCE.md),
  [M4](M4_ACCEPTANCE.md) and [M5](M5_ACCEPTANCE.md) bounded contracts.
- [Roadmap](ROADMAP.md), [next developer-alpha plan](M6_PLAN.md),
  [preview limits](../docs/release/0.1-preview.md) and
  [source identity](../SOURCE_IDENTITY.md).

## Source completeness and reference notes

The source map enumerates every published plan file with its actual bytes and
SHA256. Edition metadata records the source digest and declared editorial scope.
Some original long-form inputs had truncated endings; retained text must not be
presented as recovered missing material. Clauses and technical amendments remain
subject to the documented precedence and supersession rules.

## Public edition scope

The architecture includes future AI, compatibility, networking and hardware
requirements. Their presence is intentional product design, not a claim that
these subsystems are implemented in 0.1. Local engineering acceptance is separate
from this snapshot's validation and from official signed image publication.
