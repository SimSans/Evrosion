# ADR-0003 — Preservation-first installation and bundled Windows compatibility

Status: Accepted
Date: 2026-09-22
Owners: Project owner; future storage/lifecycle and compatibility maintainers
Related: E-010, E-012, E-016, E-019, E-022, E-025, E-026, R-011, INV-LIFE-002, INV-LIFE-003, INV-LIFE-004, INV-AUTH-001, INV-KERN-001

## Context

The owner accepted and supplied the 2026-09-21
[product amendment](../plans/amendments/Evrosion_Data_Migration_and_Windows_Compatibility_Amendment_v1.md),
and requested technical integration. The initial development
version and M0 acceptance now have separate executed evidence.

The source's A-001/A-002 labels overlap the established audit-action namespace.
They do not replace A-001 Root Authority Custody or A-002 in the audit register.
Use **ADR-0003.MIGRATION** and **ADR-0003.WINDOWS** for the product requirements;
cite the preserved amendment and section when quoting its local labels.

## Decision

1. Provide a future preservation-first installation/migration subsystem. Keep
   replaceable System Generations, Durable User State and Migration Source State
   distinct. Journal migration, verify inventory/content and health, retain the
   source while unresolved, and require explicit owner authority for reclamation.
2. Ordinary-user releases must bundle an operational Windows Compatibility
   Runtime for their declared supported software. Supported applications should
   launch without a separate compatibility-framework installation/configuration.
3. Native apps use native APIs without a compatibility runtime dependency.
   Compatibility runs on demand in userspace under scoped Evrosion authority.
   Bundling does not require always-running foreign services or foreign kernel policy.
4. Preserve M0–M5 and the 0.1 architecture-proof gate. These features may be staged
   after the native platform is ready; neither is added to 0.1 by this decision.
   Ordinary-user readiness has additional explicit product gates.

The [canonical design](../designs/INSTALLATION_AND_COMPATIBILITY.md) defines
requirements and future evidence. No installer, storage mutation or compatibility
engine is implemented or selected by this ADR.

## Invariants preserved

- INV-LIFE-002: durable state stays separate from replaceable system content.
- INV-LIFE-003 and INV-LIFE-004: health gates and protected rollback precede retirement.
- INV-AUTH-001: foreign software and migration operations gain no ambient authority.
- INV-KERN-001: installer policy and foreign OS semantics stay out of the kernel.

## Alternatives considered

Mandatory wipe-and-restore fails the accepted preservation goal. An optional
post-install Windows pack fails ordinary-user availability. Making Windows
semantics native kernel policy or starting foreign daemons for every native app
would violate the existing isolation/performance boundary. Requiring both products
for M0–M5 would change the explicitly preserved architecture-proof scope.

## Consequences and supersession

E-025.80 and E-025.118 still govern **early staging**. Any reading of “later” as
“optional forever for the ordinary-user product” is superseded by this ADR.
E-022.1's on-demand activation remains binding. E-012.25's reinstall-without-wipe
and E-010/E-019 durable-state rules are extended to foreign-OS migration, not
replaced. R-010's `.zion` name remains current; old `.sion` spellings stay intact
inside historical imports. The [roadmap](../ROADMAP.md) records these boundaries.

## Security and failure analysis

Unsupported/damaged storage, inadequate space and locked encryption must lead
to explicit constraints and safe alternatives. Legitimate credentials/recovery
material are required to unlock encrypted sources. Same-disk copies do not
replace an external backup. A copied Program Files tree does not establish
application installation or compatibility. Source reclamation remains a distinct,
explicitly authorized destructive step even after copy completion.

## Verification

Documentation integration is reviewed against the source and checked by the
architecture validator. Product implementation remains DEFERRED. Future gates
require crash/restart migration tests, verification-failure/source-preservation
tests, owner-confirmation tests and a supported-app compatibility matrix with
native independence and authority/isolation evidence.

## Migration / rollback

This is a documentation adoption; imported source bytes and M0 evidence remain
unchanged. Amend this ADR with explicit owner decisions and cross-reference
supersessions if future product direction changes. No on-disk format is frozen.

## Expiry or review trigger

Review before designing the installer, choosing a compatibility provider,
promoting a related contract, or claiming an ordinary-user release.
