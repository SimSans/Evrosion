Public technical edition. Editorial changes remove development-workspace instructions; technical requirements and clause identities remain. The source map records actual edition hashes.

# EVROSION SUPERFILE — R-007 through R-011
## Project Infrastructure, Compatibility, `.zion` Ecosystem, Knowledge Preservation, and M0/0.1 Release Gates

**Prepared:** 2026-09-21  
**Status:** CONSOLIDATED DESIGN DIRECTION — consolidated technical edition  
**Scope:** R-007, R-008, R-009, R-010, R-011  
**Intended reader:** Founder, maintainers, future maintainers and reviewers  
**Relationship to prior decisions:** This document extends R-001 through R-006 and E-001 through E-026. It does not casually reopen them.

> **Scope rule:** Implementation and governance choices follow Evrosion's established principles. Values requiring evidence or specialist review—support-window duration, marketplace launch date, cryptographic implementation details, staffing levels and legal contract text—remain explicitly deferred.

---

# 0. DOCUMENT ORGANIZATION AND AUTHORITY

Treat the five R-sections in this file as **five distinct decisions**, even though they are delivered as one file:

```text
R-007 — Project Infrastructure & Repository Operations
R-008 — Compatibility, Deprecation & Support Policy
R-009 — .zion Developer Ecosystem & Software Distribution
R-010 — Documentation, Architecture Memory & Knowledge Preservation
R-011 — M0 Public Gate & Evrosion 0.1 Developer Preview Readiness
```

When integrating this into the repository:

1. Preserve this superfile as the decision packet.
2. Create/update the canonical R-series index.
3. It is acceptable to split each R-section into its own canonical Markdown file for day-to-day use.
4. Do not silently reinterpret an R-law because an implementation shortcut is convenient.
5. If implementation evidence contradicts a rule, open an ADR/change proposal rather than quietly drifting.
6. Historical references to `.sion` in older Evrosion architecture documents refer to the format now canonically named **`.zion`**. Do not implement two formats.
7. The current package extension is **`.zion`**.
8. E-001 through E-026 remain architectural authority unless formally amended using the documented architecture-change process.
9. Running implementation/tests become the source of truth for *what currently works*, but not an excuse to silently rewrite constitutional architecture.
10. R-006 legal rules apply before accepting substantial external code.

---

# 1. CROSS-R EXECUTIVE SUMMARY

These five decisions turn Evrosion from:

```text
a well-designed operating-system architecture
```

into:

```text
a project that can safely become public,
evolve without compatibility chaos,
accept third-party software,
remember why it was built this way,
and know exactly when M0 / 0.1 are actually done.
```

The central outcomes are:

- **one official GitHub organization and one main monorepo initially;**
- **GitHub-only public project infrastructure until approximately 0.9;**
- **security-first repository defaults without expensive enterprise bureaucracy;**
- **CI as evidence, not ceremony;**
- **backups outside GitHub because GitHub is infrastructure, not the project's only memory;**
- **stable public APIs are deliberate promises, not accidental exports;**
- **0.x APIs are unstable unless explicitly promoted;**
- **Platform API Level remains separate from human OS release version;**
- **compatibility is maintained through versioned contracts, side-by-side mechanisms and migrations rather than freezing implementations;**
- **the `.zion` format is open, store-independent and offline-capable;**
- **the official software catalog/marketplace is optional infrastructure, never a monopoly on installing software;**
- **no arbitrary privileged install scripts; installation is declarative/transactional;**
- **app permissions are capability requests, not authority automatically granted by a package signature;**
- **package versions become immutable once formally published;**
- **documentation lives with the code and is versioned like code;**
- **one master index, not one enormous permanently edited master document;**
- **ADRs preserve why decisions changed;**
- **AI context packs are derived from canonical docs and are never canonical themselves;**
- **M0 engineering completion and “safe to make the repo public” are separate gates;**
- **0.1 remains a QEMU-first Developer Preview and is blocked by proof failures, not by missing consumer features.**

---

# R-007 — PROJECT INFRASTRUCTURE & REPOSITORY OPERATIONS

## R-007.1 Purpose

R-007 defines the operational substrate around Evrosion development:

- GitHub organization structure;
- repository layout;
- permissions;
- CI;
- Actions security;
- secrets;
- dependency intake;
- build/release automation;
- backups;
- artifact retention;
- supply-chain evidence;
- maintainer access;
- disaster recovery.

The goal is not enterprise bureaucracy.

The goal is:

> **A compromised contributor account, CI workflow, dependency, laptop, or GitHub feature should not be able to silently rewrite Evrosion history or publish an Official Evrosion release.**

---

## R-007.2 One Official GitHub Organization

Public Evrosion development should live under an official GitHub organization.

The founder controls the organization during the founder era under R-002.

Benefits:

- project identity is separate from a personal repository;
- team/repository permissions can evolve cleanly;
- future Foundation transition is easier;
- additional repositories can be added without namespace fragmentation;
- organization-level security/audit capabilities are available;
- project continuity does not depend on a repository living forever under one personal username.

GitHub remains the canonical public home until approximately 0.9 under R-005.

---

## R-007.3 Start as a Monorepo

Evrosion should begin with one primary monorepo.

Reason:

Early OS development requires atomic changes across:

```text
kernel
IDL/contracts
userspace services
build system
tests
.zion tooling
developer CLI
documentation
```

Prematurely splitting those into many repositories creates:

- cross-repository version coordination;
- more CI;
- more permissions;
- harder AI context;
- harder atomic refactors;
- harder bisects;
- duplicated issue tracking.

Use additional repositories only when something has a genuinely independent lifecycle or security boundary.

Possible later repositories:

```text
evrosion                      # main OS/platform
evrosion-sdk                  # if independent release cadence becomes real
evrosion-specs                # if interoperability specs need independent lifecycle
evrosion-security-private     # private incident/security coordination if needed
evrosion-infrastructure       # deployment infra if separation becomes valuable
```

Do not split because the top-level directory looks large.

---

## R-007.4 Repository Structure Mirrors Architecture

The source tree should follow subsystem ownership and architecture.

Avoid permanent dumping grounds such as:

```text
misc/
utils_stuff/
temp/
old/
new2/
final_final/
```

Cross-cutting helpers should exist only when they are genuinely cross-cutting.

The repository structure should make it possible for a newcomer to roughly infer the architecture without reading every source file.

---

## R-007.5 Main Branch Is Canonical

The canonical integration branch is:

```text
main
```

Formal releases are derived from identifiable commits/tags on canonical history.

No force-pushing or deletion of canonical release history.

Experimental feature branches may be rebased/rewritten before merge.

Published formal tags/releases are immutable under R-003/R-005.

---

## R-007.6 Early Founder Workflow vs Mature Workflow

### Early solo stage

The founder may retain bypass authority so development does not become PR bureaucracy for one person plus maintainers.

However:

- CI results remain visible;
- formal release gates cannot be skipped silently;
- outside contributors use pull requests;
- release publication remains a deliberate operation.

### Mature stage

As trusted maintainers exist:

- normal changes use review;
- security-critical code gets additional review under R-004;
- direct main-branch pushes become exceptional;
- merge/release permissions narrow by role.

Process must grow with people.

Do not fake a five-person review process when only one qualified person exists.

---

## R-007.7 Repository Rules From Public Launch

When the public repo opens, configure protections that GitHub supports for public repositories even on free organization plans.

Minimum:

- block force-push to `main`;
- block deletion of `main`;
- require relevant status checks;
- require PRs for outside contributions;
- restrict canonical/release branch pushes;
- protect release tags where possible;
- require conversation resolution for reviewed PRs where useful.

GitHub currently provides repository rulesets and protected branches for public repositories on GitHub Free / Free for organizations.

The founder may retain an explicit emergency bypass during the founder era.

---

## R-007.8 Authentication

Require secure 2FA for organization members with privileged project access.

Preferred:

```text
passkey
hardware security key
authenticator app
```

Avoid treating SMS as the desired high-privilege baseline.

The founder should maintain:

- at least two independent strong authentication methods;
- recovery material stored offline;
- no single phone as the sole route back into the project.

GitHub supports organization-level 2FA requirements and can require secure 2FA methods.

---

## R-007.9 Organization Owners

Early stage:

```text
Founder = primary/sole organization owner
```

This preserves active-founder authority and avoids casually creating another super-admin.

As soon as there is a genuinely trusted continuity structure, add a carefully controlled recovery/continuity owner rather than allowing the entire project's recovery path to depend forever on one personal account.

Ordinary target later:

```text
1–2 organization owners
```

not a large admin group.

OpenSSF guidance recommends tightly limiting organization owners/admins.

---

## R-007.10 Least Privilege

Default organization/repository permissions should be restrictive.

A contributor does not need write access merely to contribute.

Progression should resemble:

```text
outside contributor
→ recurring contributor
→ triage/review role
→ subsystem maintainer
→ narrowly scoped write/merge authority
→ rare admin/owner authority
```

Administrative access is infrastructure authority, not a badge of appreciation.

---

## R-007.11 GitHub Actions Default Permissions

Set the default `GITHUB_TOKEN` posture to read-only where practical.

Each workflow/job requests only the permissions it needs.

Example principle:

```text
build/test job:
contents: read

release-attestation job:
contents: read
id-token: write
attestations: write
```

Do not give broad write permissions to every CI workflow.

GitHub explicitly recommends limiting `GITHUB_TOKEN` permissions to the minimum required.

---

## R-007.12 Pin Third-Party Actions

Third-party GitHub Actions used in security/release-sensitive workflows should be pinned to a full commit SHA rather than a floating tag.

GitHub's current security guidance states that pinning to a full-length commit SHA is the only way to consume an Action as an immutable revision.

Automation may periodically propose reviewed SHA updates.

Never allow:

```yaml
uses: random-owner/action@main
```

in a release-trust workflow.

---

## R-007.13 Prefer OIDC Over Long-Lived Cloud Secrets

If Evrosion later uses cloud storage/build/publishing infrastructure that supports OIDC:

```text
GitHub workflow identity
→ short-lived token
→ narrowly scoped external access
```

instead of:

```text
long-lived cloud API key
stored forever in GitHub secrets
```

GitHub supports OIDC precisely to remove the need to duplicate long-lived cloud credentials.

---

## R-007.14 Release Environment Is Protected

Formal publication should use a protected release environment/process.

Once staffing permits:

- restrict which branch/tag can publish;
- require explicit approval for release publication;
- prevent self-approval when a second qualified person exists;
- expose release secrets only after the gate;
- record publication events.

Early solo stage may use founder approval alone, but the separation between:

```text
build candidate
```

and:

```text
publish Official release
```

must exist conceptually from the start.

---

## R-007.15 Official Release Keys Are Not Ordinary CI Secrets

Long-term Stable/Official signing authority must not live as a normal reusable GitHub repository secret.

R-003 remains authoritative.

Progression may be:

```text
early development signing key
→ protected release key
→ hardware/offline/threshold root model when maturity justifies it
```

GitHub Actions may produce provenance/attestations.

That does not make GitHub the permanent sole root of Official Evrosion trust.

---

## R-007.16 Fork Pull Requests Are Untrusted Code

Never run arbitrary fork-submitted code on a privileged persistent self-hosted runner with secrets or sensitive local state.

If self-hosted runners become necessary for QEMU/KVM or hardware testing:

- use disposable/ephemeral workers for untrusted code;
- isolate networks/credentials;
- wipe state between runs;
- separate privileged release runners from contributor CI.

A pull request is executable attacker-controlled input until reviewed.

---

## R-007.17 CI Lanes

Use several layers rather than one monstrous all-or-nothing workflow.

### Fast PR lane

Target minutes, not hours:

- format;
- lint;
- compile;
- unit tests;
- cheap contract tests;
- license/dependency checks;
- basic static analysis.

### Architecture lane

- architecture fitness tests;
- capability invariants;
- forbidden-dependency checks;
- contract compatibility checks;
- exception-register validation.

### QEMU smoke lane

- boot;
- serial signature;
- panic capture;
- selected component startup;
- expected shutdown/reset behavior.

### Deep lane

Run on main/nightly/manual as appropriate:

- full QEMU integration;
- randomized/fault injection;
- fuzzing;
- reproducibility comparison;
- performance regressions;
- power-loss/storage tests once M3 exists;
- security scanners.

### Release lane

- clean build from release commit;
- full release gate;
- SBOM;
- provenance;
- reproducibility evidence;
- signatures;
- release publication.

---

## R-007.18 CI Is Evidence, Not Authority

A green CI badge does not automatically create an Official release.

CI proves particular facts.

Release authority remains explicit.

Likewise:

```text
CI failure
```

must not be casually bypassed by renaming/removing the failing test.

If a test is wrong, fix or formally retire the test with justification.

---

## R-007.19 Reproducibility From Early Development

Keep the existing PRE-M0 rule:

- pinned Rust/toolchain;
- pinned bootloader/dependencies;
- deterministic image construction;
- normalized generated metadata where possible;
- build identity tied to source revision.

As soon as practical, CI should build the same source in two independent clean locations and compare output.

Perfect reproducibility may require iteration.

Vague claims of “reproducible” are not enough.

---

## R-007.20 Dependency Intake

Every new dependency is:

```text
code we did not write
+
license we must obey
+
supply-chain authority we are importing
+
future maintenance cost
```

PR review should expose dependency additions clearly.

Use:

- Cargo lockfiles;
- checksum verification;
- GitHub dependency review where applicable;
- Dependabot/advisory alerts;
- R-006 license policy;
- security review for sensitive dependencies.

GitHub's dependency review can identify added/removed dependencies, known vulnerabilities and licensing information in pull requests.

---

## R-007.21 Code Scanning

Enable CodeQL for supported languages, especially Rust once the public repository exists.

GitHub currently supports Rust analysis in CodeQL and provides code scanning to public repositories.

CodeQL complements:

- Rust compiler safety;
- Clippy;
- fuzzing;
- architecture tests;
- human review.

It does not replace them.

---

## R-007.22 Secret Scanning

Enable GitHub secret scanning/push protection features available to the project.

Before public launch, independently audit existing Git history for:

- tokens;
- SSH/private keys;
- API credentials;
- cloud keys;
- personal data;
- private repository URLs;
- signing material.

Once a secret has been committed publicly:

> removing the line is not enough.

Revoke/rotate the secret.

GitHub secret scanning examines Git history, not merely the current branch tip.

---

## R-007.23 Dependency/License Automation

As the repository matures, CI should automatically enforce R-006.

Candidate tooling:

```text
cargo-deny
cargo-about
REUSE
SPDX tooling
SBOM generation
custom component-license map validation
```

Exact tools are replaceable.

The law is not.

---

## R-007.24 SBOM

Formal releases should eventually produce an SBOM.

Preferred interoperable standard:

```text
SPDX
```

SPDX 3.0 is the current major specification as of this document.

The SBOM should identify enough information to answer:

- what shipped;
- exact versions;
- source/dependency identity;
- licenses;
- hashes/relationships where applicable.

---

## R-007.25 Build Provenance

Use SLSA concepts as a maturity target, not a marketing checkbox.

Current SLSA 1.2 distinguishes:

```text
Build L1 — provenance exists
Build L2 — signed provenance from hosted build platform
Build L3 — hardened build platform
```

Evrosion should begin producing useful provenance early and improve it as the release pipeline matures.

Do not claim a SLSA level until the actual requirements are met.

---

## R-007.26 GitHub Artifact Attestations

GitHub public repositories can produce artifact attestations that connect artifacts to:

- workflow;
- repository;
- organization;
- commit SHA;
- triggering event.

Use them as supplemental public evidence.

They do not replace:

- Evrosion signing;
- reproducible builds;
- R-003 trust;
- independent rebuild verification.

---

## R-007.27 Cache Is Never Authority

Build caches may improve speed.

A cache hit must never be treated as proof that:

- the artifact is authentic;
- tests ran;
- source matches;
- release approval happened.

Release builds should be capable of clean reconstruction.

---

## R-007.28 Generated Artifacts

Do not commit large generated binaries simply because it is convenient.

Prefer:

```text
source + reproducible generation
```

Formal images belong in authenticated release artifacts.

Small deterministic fixtures may live in Git where useful.

Large test images/firmware blobs require explicit provenance/license handling.

---

## R-007.29 Avoid Core Git Submodule Dependency

Avoid making critical Evrosion build paths depend on a forest of Git submodules.

They create:

- detached revision confusion;
- recursive checkout complexity;
- provenance friction;
- poor newcomer UX.

Use language/package dependency mechanisms, vendoring with explicit provenance, or clearly managed external source snapshots when needed.

Submodules remain possible for exceptional cases, not the default architecture.

---

## R-007.30 Repository Backups

GitHub is not the only copy of Evrosion.

Maintain recoverable backups outside GitHub.

At minimum:

- mirrored Git repository with full history/tags;
- release metadata/signatures;
- project documentation;
- critical organization/repository configuration export/checklist;
- issue/discussion/project metadata where practical.

GitHub's official backup guidance supports mirror clones and migration archives/other tooling.

---

## R-007.31 Backup Locations

Mature target:

```text
GitHub
+
independent online/offsite backup
+
periodic offline/encrypted copy
```

Do not place every copy under one cloud account.

Exact provider is replaceable.

---

## R-007.32 Restore Testing

A backup that has never been restored is a theory.

Periodically test:

```text
new empty location
→ restore repo
→ recover tags
→ build
→ access required project metadata
```

Frequency increases with project importance.

---

## R-007.33 GitHub Audit Logs

As membership grows, review GitHub organization audit logs during:

- suspected compromise;
- permission changes;
- release incident;
- owner/admin changes;
- periodic security review.

GitHub's organization audit log records who performed actions and when.

---

## R-007.34 Infrastructure as Code

Where practical, store reproducible project configuration in the repository:

- CI workflows;
- lint policy;
- dependency policy;
- release scripts;
- labels/templates;
- build manifests;
- test definitions.

GitHub-only UI settings that cannot be represented as code should be documented in an `ops/` runbook/checklist.

---

## R-007.35 Failure of GitHub Must Not Kill Evrosion

A temporary GitHub outage should not prevent:

- local builds;
- already-installed Evrosion from running;
- offline recovery;
- source reconstruction from backups.

A permanent GitHub account loss should be survivable through:

- off-platform source backups;
- trademark/project identity;
- R-003 trust root;
- documented recovery path.

GitHub is hosting.

GitHub is not Evrosion's constitutional root.

---

## R-007.36 Cost Discipline

The early baseline should rely heavily on features available to public GitHub repositories for free:

- public repositories;
- rulesets/branch protection;
- CodeQL/code scanning;
- secret scanning;
- dependency review;
- Actions within practical limits;
- Discussions;
- Releases.

Do not buy enterprise infrastructure simply to look professional.

Spend when the project actually needs scale/security capabilities unavailable at the current tier.

---

## R-007.37 Adversarial Findings

### Compromised maintainer pushes malicious main commit
**Control:** restricted write authority + rules/status checks + audit trail + review as staff exists.

### Compromised CI action
**Control:** pin external Actions to full commit SHA; least-privilege token.

### Fork PR steals release credentials
**Control:** no sensitive credentials on untrusted PR runners; protected release environment.

### GitHub account lost
**Control:** strong multi-factor auth + recovery material + external backups.

### GitHub itself disappears
**Control:** source/release metadata mirrored independently; trust root not GitHub-exclusive.

### Dependency turns malicious
**Control:** lockfile, review, license/security scanning, provenance, update review.

### AI generates huge unsafe change that passes shallow tests
**Control:** architecture fitness lane + subsystem tests + human accountability.

### Solo founder gets blocked by enterprise bureaucracy
**Control:** maturity-scaled process and explicit founder bypass in early phase.

### Release job can publish whatever it builds
**Control:** candidate build and Official publication are separate authorities.

---

## R-007.38 Locked Laws

1. Evrosion uses an official GitHub organization.
2. Evrosion begins as a main monorepo.
3. `main` is canonical integration history.
4. Formal release history must not be rewritten.
5. Repository protections activate at public launch.
6. Founder may retain explicit early bypass authority.
7. Privileged organization members use strong 2FA.
8. Administrative access remains rare.
9. GitHub Actions default toward least privilege.
10. Security-sensitive third-party Actions are pinned by full commit SHA.
11. OIDC/short-lived credentials are preferred over long-lived cloud secrets.
12. Fork PR code is treated as untrusted.
13. Privileged/release self-hosted runners must not execute arbitrary untrusted PR code.
14. CI is layered into fast, architecture, QEMU/deep and release evidence.
15. Official publication is a separate authority from successful build.
16. Toolchains/dependencies remain pinned/reproducible.
17. Dependency additions receive explicit review.
18. CodeQL/secret scanning/dependency review are enabled where useful/available.
19. R-006 license compliance becomes automated as tooling matures.
20. Formal releases produce SBOM/provenance as maturity allows.
21. GitHub attestations supplement but do not replace R-003.
22. Build caches are never trust evidence.
23. Core development avoids unnecessary Git submodules.
24. Evrosion maintains off-GitHub backups.
25. Backups are periodically restore-tested.
26. GitHub is infrastructure, not the root of Evrosion identity/trust.
27. Security process scales with actual staffing and funding.
28. No expensive enterprise stack is required merely for appearances.

---

# R-008 — COMPATIBILITY, DEPRECATION & SUPPORT POLICY

## R-008.1 Purpose

Evrosion must evolve for decades without becoming either:

```text
frozen forever
```

or:

```text
a platform where every update randomly breaks software
```

E-026 already established:

> **Stable laws, replaceable implementations, compatibility windows, side-by-side migration.**

R-008 turns that into a concrete developer/support policy.

---

## R-008.2 Compatibility Is Multi-Dimensional

Never say merely:

> “Evrosion is backwards compatible.”

Track distinct compatibility classes:

```text
source compatibility
binary compatibility
behavioral compatibility
contract/protocol compatibility
package-format compatibility
persistent-data compatibility
driver compatibility
hardware support compatibility
configuration compatibility
```

A change may preserve one and break another.

Release notes and developer tooling should identify the relevant class.

---

## R-008.3 Human Release Version Is Not the Compatibility Contract

Keep E-026's version identities separate:

```text
Evrosion Release          — human/product milestone
System Generation         — concrete installed system state
Platform API Level        — stable app/developer platform surface
Contract major/minor      — individual typed protocol
ABI fingerprint           — concrete binary interface details
Package version/build ID  — specific software package identity
State schema epoch        — persistent-data format identity
```

Do not use `Evrosion 2.0` to answer every one of those questions.

---

## R-008.4 Stability Classes

Public interfaces should carry a maturity state.

Recommended conceptual states:

```text
EXPERIMENTAL
PREVIEW
STABLE
DEPRECATED
```

### Experimental

- may change/remove rapidly;
- no compatibility promise;
- used to learn.

### Preview

- intended direction is becoming real;
- breaking changes still possible;
- changes require notice/documentation.

### Stable

- explicit compatibility promise;
- tested/documented;
- removal requires formal deprecation/migration process.

### Deprecated

- still supported for a transition;
- replacement/documentation exists;
- eventual removal is planned.

Do not create dozens of maturity words.

---

## R-008.5 0.x Rule

Until Evrosion's platform reaches 1.0 maturity:

> **Public-looking API does not automatically mean Stable.**

0.x APIs are considered Experimental/Preview unless explicitly marked Stable.

This prevents a prototype struct layout from becoming a ten-year ABI promise because somebody happened to use it.

---

## R-008.6 Stability Requires Deliberate Promotion

An API/contract becomes Stable only after:

- semantics are understood;
- security model is clear;
- capability implications are clear;
- documentation exists;
- compatibility tests exist;
- failure behavior is defined;
- versioning/migration strategy exists.

Stabilization is a project decision.

It is not accidental exposure.

Rust's “stability without stagnation” model is useful precedent: stable features are strong promises, while newer/unstable features can evolve before promotion.

---

## R-008.7 App Manifest Platform Requirements

A `.zion` application should eventually declare at least:

```text
minimum supported Platform API Level
targeted/tested Platform API Level
required contract/features
architecture requirements
```

Conceptually similar to Android's separation between minimum and target API levels.

Do **not** require a maximum platform version by default.

An old app should normally continue forward unless a real incompatibility/security reason prevents it.

---

## R-008.8 Target Level Can Control Compatibility Behaviors

When platform behavior must evolve, Evrosion may retain compatibility behavior based on the Platform API level an application targets.

Example concept:

```text
old app target
→ receives legacy-compatible behavior

new app target
→ receives new behavior
```

This can be cleaner than preserving every old semantic globally forever.

Compatibility behavior must still respect security invariants.

---

## R-008.9 Stable APIs Should Survive Across Compatibility Windows

Once a developer-facing API is Stable, Evrosion should preserve it through a meaningful compatibility window.

Exact number of Platform API Levels/years is deliberately deferred until:

- ecosystem size;
- maintenance cost;
- usage data that does not require invasive telemetry;
- security burden;
- developer feedback

are known.

Do not promise “forever” before 1.0.

Do not break Stable casually either.

---

## R-008.10 Deprecation Process

Normal Stable deprecation path:

```text
1. mark Deprecated
2. document replacement
3. SDK/compiler/tooling warns
4. migration guide/tool where practical
5. keep compatibility through announced window
6. remove only at a version boundary that permits removal
```

No surprise disappearance.

Kubernetes provides useful precedent by requiring versioned API changes rather than silently removing fields from the same API version.

---

## R-008.11 Emergency Security Exception

Compatibility is important.

Security invariants are more important.

If preserving a compatibility behavior creates a serious unavoidable vulnerability:

- warn clearly;
- provide mitigation/migration;
- break only the minimum necessary surface;
- explain the reason publicly;
- provide compatibility alternative where feasible.

Do not preserve known exploitable behavior merely because it was once Stable.

---

## R-008.12 Contract Versioning

Typed Evrosion contracts use major/minor versions.

Conceptual rule:

```text
minor:
backward-compatible/additive change

major:
incompatible semantic change
```

A service can temporarily support multiple major versions side-by-side during migration.

This is one of Evrosion's main mechanisms for avoiding global flag-day upgrades.

---

## R-008.13 No Ambient Private Contract Use

Internal/private contract endpoints are not public compatibility promises.

Applications should not discover undocumented service endpoints and then claim Evrosion broke them later.

Developer tools/documentation must clearly distinguish:

```text
public supported interface
vs
internal implementation interface
```

Layer 3 may inspect anything.

Inspection does not convert an internal surface into a support contract.

---

## R-008.14 Kernel Internal ABI Is Not Public Stable API

Evrosion should not promise a stable kernel-internal ABI for arbitrary out-of-tree kernel modules.

The architecture deliberately prefers userspace services/drivers.

This allows kernel internals to evolve without freezing implementation details forever.

External hardware/software integrations should target documented capability/driver contracts rather than private kernel structures.

---

## R-008.15 Driver Compatibility

Drivers should declare:

- driver API/contract version;
- supported hardware identifiers;
- architecture;
- required capabilities;
- minimum platform level;
- package identity/version.

Userspace driver boundaries should absorb most compatibility evolution.

If a driver contract changes incompatibly:

```text
old contract implementation
+
new contract implementation
```

may coexist through migration where reasonable.

---

## R-008.16 `.zion` Format Versioning

The `.zion` container/manifest format has its own version.

Do not tie it directly to Evrosion release number.

Recommended model:

```text
format major.minor
```

### Minor

- additive;
- old readers can ignore explicitly ignorable fields;
- required-field semantics do not silently change.

### Major

- incompatible parse/semantic change;
- old system rejects with clear “unsupported package format” rather than guessing.

The canonical extension remains:

```text
.zion
```

---

## R-008.17 Historical `.sion` Rename

Earlier E-025 documents used `.sion`.

That name has been superseded by the user's later decision:

```text
.sion → .zion
```

This is a naming migration, not two package formats.

Living documentation/code should use `.zion`.

Archived historical snapshots may preserve original wording with a supersession note.

---

## R-008.18 Persistent State Compatibility

Persistent user/system state is more dangerous to break than code.

State has a schema epoch/version.

Migration rules:

- migrations are explicit;
- migrations are testable;
- update activation is transactional;
- rollback compatibility is considered before migration;
- destructive/irreversible transformations require deliberate safeguards.

Known Good must not become useless because a new generation irreversibly mutated the only copy of state without a rollback plan.

---

## R-008.19 Side-by-Side State Migration

When practical:

```text
old schema
→ create/convert new representation
→ validate
→ switch
```

rather than editing the only durable state in place.

For huge datasets where copying is unreasonable, use journals/checkpoints/compatible migration mechanisms appropriate to the subsystem.

---

## R-008.20 Configuration Formats

Machine configuration formats exposed to users/tools should have explicit schema versions.

Unknown required fields should produce clear failure rather than silently being discarded if that would change meaning.

Config migration should be deterministic and logged.

---

## R-008.21 CLI Compatibility

The `ev` developer CLI evolves rapidly before 1.0.

Human-readable text output is not a stable machine interface.

Where scripts need stability, provide explicit machine output such as:

```text
--format json
```

with a versioned schema.

This prevents scripts from parsing decorative terminal sentences forever.

---

## R-008.22 App Dependencies

Evrosion should avoid forcing applications into a global shared-library dependency maze.

Preferred normal application model:

```text
application bundles its private third-party runtime/libs
+
depends on stable Evrosion platform contracts
```

Evrosion may content-deduplicate identical blobs internally.

This gives:

- fewer dependency conflicts;
- easier rollback;
- reproducible application identity;
- simpler compatibility.

Core platform libraries/services remain platform-managed.

---

## R-008.23 Native Apps Do Not Pay for Compatibility Layers

E-026 remains authoritative:

> native software should not pay the complexity/performance cost for optional legacy compatibility mechanisms.

Windows/Linux compatibility personalities are optional layers.

They must not become architectural dependencies of normal Evrosion applications.

---

## R-008.24 Support Stream

Keep R-004's rolling technical support model.

Conceptually:

```text
Current Supported Stable
Recent Grace/Transition generations as capacity allows
Unsupported historical generations
```

Exact number/duration remains deferred.

Security engineering follows the supported stream rather than maintaining every historical branch forever.

---

## R-008.25 Unsupported Does Not Mean Disabled

End of support must not remotely brick or deactivate an old Evrosion installation.

An unsupported generation may continue to:

- boot;
- run offline;
- access owner data;
- use Layer 3;
- be restored locally.

It simply no longer receives the normal security/support guarantee.

Known severe vulnerabilities are still publicly disclosed under R-004.

---

## R-008.26 Commercial/Legal Support Periods

The rolling internal model does not prevent a commercial product, OEM device or jurisdiction from requiring an explicit support commitment.

Before Evrosion Systems places a commercial product/device on a market:

```text
declare an applicable support period
+
align security/update obligations with law and contract
```

This is especially relevant in the EU.

As of 2026-09-21:

- EU Cyber Resilience Act manufacturer reporting obligations began 2026-09-11;
- main CRA product obligations apply from 2027-12-11;
- the CRA includes support-period/vulnerability-handling obligations for in-scope products.

Exact applicability depends on how Evrosion is commercialized and must be reviewed legally at that stage.

This does **not** block non-commercial M0/0.1 public development.

---

## R-008.27 Hardware Support States

Use clear hardware status labels.

Recommended:

```text
CERTIFIED
SUPPORTED
COMMUNITY-VERIFIED
EXPERIMENTAL
UNSUPPORTED
KNOWN-BROKEN
```

Definitions must be public.

A single successful boot is not certification.

---

## R-008.28 Certified vs Supported

### Certified

Passed the formal Evrosion Certified process for a defined configuration/support period.

### Supported

Evrosion project actively intends the hardware/configuration to work and accepts regressions as project bugs.

### Community-Verified

Users report working behavior, but Evrosion does not promise engineering coverage.

### Experimental

Known incomplete/unstable.

### Unsupported

No active promise.

### Known-Broken

Known not to work correctly.

---

## R-008.29 Hardware Support Is Configuration-Specific

A laptop model name may hide:

- different Wi-Fi devices;
- different GPUs;
- different storage controllers;
- different firmware;
- different panel/input hardware.

Support records should identify meaningful hardware/firmware details.

Do not overclaim support based on retail model name alone.

---

## R-008.30 Compatibility Test Corpus

Stable compatibility promises must become executable tests.

Maintain fixtures such as:

- old `.zion` packages;
- old manifests;
- previous contract clients;
- previous state schemas;
- previous configuration files;
- representative old app binaries.

A Stable promise that is never exercised will eventually be broken accidentally.

---

## R-008.31 Breaking-Change Evidence

A proposed breaking Stable change must answer:

```text
Why is it necessary?
Who breaks?
Is there a compatibility shim?
Is there a migration tool?
Can versions coexist?
What is the security/performance cost of retaining compatibility?
What user data is at risk?
What is the removal schedule?
```

“Cleaner code” alone is usually not enough.

---

## R-008.32 Adversarial Findings

### Everything accidentally becomes permanent
**Control:** 0.x unstable by default; deliberate Stable promotion.

### Platform can never improve
**Control:** target API levels, contract majors, compatibility shims and side-by-side migration.

### Old apps die every release
**Control:** Stable API windows + compatibility test corpus.

### Old app forces insecure behavior forever
**Control:** narrowly scoped security exception + migration.

### Driver freezes kernel internals
**Control:** userspace/public driver contracts; no stable private kernel ABI.

### Data migration kills rollback
**Control:** versioned schemas + transactional migration + Known Good awareness.

### Package parser interprets future format incorrectly
**Control:** explicit `.zion` format major/minor and fail-closed unsupported-major behavior.

### Old unsupported install is remotely disabled
**Control:** support ending never bricks the owner's machine.

---

## R-008.33 Locked Laws

1. Compatibility is explicitly categorized, not treated as one vague concept.
2. Release version is separate from compatibility identities.
3. Public interfaces have Experimental/Preview/Stable/Deprecated maturity.
4. 0.x interfaces are unstable unless explicitly promoted.
5. Stability promotion requires docs/tests/security/semantics.
6. `.zion` apps declare platform/contract requirements.
7. Target API level may select compatibility behavior where useful.
8. Stable APIs receive meaningful compatibility windows.
9. Exact compatibility-window duration is deferred until evidence exists.
10. Stable removals use formal deprecation/migration.
11. Serious security may justify minimal explicit breakage.
12. Typed contract major/minor rules govern protocol evolution.
13. Internal contracts are not accidental public APIs.
14. Kernel internals are not promised as a stable external module ABI.
15. Driver compatibility is expressed through versioned public contracts.
16. `.zion` format versioning is independent of OS release version.
17. `.zion` is the canonical extension; `.sion` is historical superseded naming.
18. Durable state uses explicit schema epochs/migrations.
19. Migration must preserve rollback/recovery intent.
20. Machine-consumable CLI output is explicitly versioned.
21. Apps should bundle private dependencies rather than depend on fragile global library sets.
22. Native apps do not depend on optional legacy compatibility layers.
23. Security support rolls forward with current Stable.
24. Unsupported systems remain owner-usable and are not remotely bricked.
25. Commercial products may require explicit legally/contractually declared support periods.
26. Hardware support states are explicit and configuration-specific.
27. Stable compatibility promises are tested with historical fixtures.
28. Breaking Stable changes require documented evidence and migration rationale.

---

# R-009 — `.zion` DEVELOPER ECOSYSTEM & SOFTWARE DISTRIBUTION

## R-009.1 Purpose

R-009 defines how third-party software exists on Evrosion.

It deliberately separates:

```text
.zion package format
publisher identity
application identity
package signature
runtime authority
software repository
official marketplace
payment
certification
```

Collapsing these concepts would recreate many existing ecosystem problems.

---

## R-009.2 `.zion` Is a Format, Not a Store

The `.zion` package format must work without the official marketplace.

Users/developers can receive `.zion` packages through:

- local files;
- removable media;
- source builds;
- third-party repositories;
- direct developer distribution;
- official Evrosion repository/marketplace later.

The official store is a convenience/trust/discovery channel.

It is not the legal or technical gatekeeper for running software.

---

## R-009.3 Offline Installation Is First-Class

A valid package can be installed offline.

At 0.1, the minimal development path may simply be:

```text
ev install ./Hello.zion
```

No network.

No account.

No marketplace.

No cloud dependency.

This directly supports Evrosion's local/offline-first principles.

---

## R-009.4 Minimal 0.1 `.zion`

The existing E-025 minimal package concept remains.

Current name:

```text
.zion
```

Minimum concept:

- manifest;
- E-016 AppIdentity;
- executable payload;
- resources;
- required contracts/platform level;
- capability declarations;
- content hashes;
- format version;
- build/package identity.

Full ecosystem metadata can come later.

---

## R-009.5 Package Manifest Is Declarative

The package manifest describes facts/requirements.

It should not be an arbitrary privileged program.

Examples:

```text
AppIdentity
display name
package version
format version
Platform API requirement
architecture
entry points
requested capabilities
content hashes
resources
publisher/signature metadata
update identity
license metadata
```

Unknown required semantics fail clearly.

---

## R-009.6 No Arbitrary Root Install Scripts

Evrosion should not recreate unrestricted:

```text
preinstall.sh as root
postinstall.sh as root
```

as the normal package model.

Installation is transactional and declarative.

If a package needs setup logic:

- do it inside its sandbox at first run; or
- use an explicitly modeled lifecycle operation with narrowly scoped capabilities.

The package should never receive ambient system authority merely because it is being installed.

OpenSSF software-repository guidance explicitly calls out secure-by-default package managers and limiting dangerous install-script behavior as a supply-chain concern.

---

## R-009.7 Package Signature Does Not Grant Authority

A valid signature answers something like:

> “This package was signed by the expected publisher/build identity.”

It does **not** mean:

> “This package may access every file, microphone, camera, network secret or system service.”

Runtime authority is still capability-mediated.

Publisher trust and runtime privilege are different.

---

## R-009.8 Capability Declarations Are Requests

A `.zion` manifest declares capabilities the application may need.

The package cannot mint them itself.

Actual grants are made through Evrosion's authority model.

Updates that add materially new capability requests should be surfaced to the owner according to Layer policy.

An old permission grant does not automatically expand because a new version asks for more.

---

## R-009.9 AppIdentity Remains Canonical

Do not redefine E-016 AppIdentity casually inside package infrastructure.

The registry/store uses AppIdentity as a stable security identity.

Human-facing package names are not security identity.

Changing:

```text
"Cool Editor"
```

to:

```text
"Cool Editor 2"
```

must not create a new authority identity accidentally.

---

## R-009.10 Publisher Identity Is Separate

Publisher identity answers:

> who is authorized to publish updates for this app/package?

It is not the same as:

- AppIdentity;
- developer display name;
- signing key;
- marketplace account.

Signing keys must be rotatable without forcing applications to become new identities.

The package ecosystem needs a documented key-rotation/delegation mechanism before large-scale publishing.

---

## R-009.11 Package Versions Are Immutable

Once a formal repository version such as:

```text
com.example.editor 1.4.2
```

is published, its bytes/hash must not be silently replaced.

If broken:

```text
yank 1.4.2
publish 1.4.3
```

Do not mutate history.

OpenSSF package-repository guidance specifically recommends policies preventing versions from being replaced and preventing deleted identities from being trivially reused.

---

## R-009.12 Yanking vs Deleting

Preferred model:

### Yank

- version remains historically identifiable;
- new installs/resolution avoid it;
- existing lockfiles/installations can understand what it was;
- security advisory may attach.

### Hard delete

Reserved for exceptional legal/malware/safety cases.

Even then:

- preserve a tombstone;
- do not allow another publisher to reuse the same identity/version deceptively.

---

## R-009.13 Package Names Are Not Recycled Casually

Prevent namespace resurrection attacks.

A package/application identity that becomes abandoned should not simply be handed to a random new actor who can publish a malicious “update” to existing users.

Transfers require a deliberate ownership process.

High-value package transfers may require:

- old-owner authorization;
- delay;
- maintainer notification;
- new-key verification;
- public audit record.

---

## R-009.14 Official Repository Security Maturity

When an official networked repository eventually exists, use OpenSSF package-repository security principles as a baseline.

Maturity should include progressively:

- verified accounts;
- MFA;
- phishing-resistant MFA for high-value publishers;
- scoped publish credentials;
- role separation;
- suspicious-package reporting;
- immutable package versions;
- vulnerability warnings;
- provenance;
- transparency/audit history;
- short-lived trusted-publisher credentials.

Do not build all of this before networking exists.

Design for it now.

---

## R-009.15 Trusted Publishers / OIDC

Long-term, automated package publishing should prefer:

```text
trusted CI identity
→ short-lived OIDC exchange
→ package-specific publish authority
```

instead of developer tokens that remain valid for years.

OpenSSF specifically recommends OIDC-based trusted publisher models at higher repository maturity.

---

## R-009.16 Repository Metadata Uses R-003 Trust Principles

The official package repository should use TUF-like authenticated metadata/properties to resist:

- malicious mirrors;
- rollback;
- freeze;
- mix-and-match;
- key compromise.

The current TUF specification explicitly targets these attacks and separates root/targets/snapshot/timestamp trust roles.

Evrosion does not need to clone TUF byte-for-byte.

It should preserve the security properties.

---

## R-009.17 Repository Is Not a Trust Monolith

The official repository should not possess a magical key that means:

> any byte the server returns may execute with unlimited trust.

Separate:

```text
repository metadata trust
publisher/package identity
runtime capability authority
OS release trust
```

Compromise of one layer should not automatically imply compromise of all others.

---

## R-009.18 Multiple Repositories Are Possible

Layer 3 must be able to configure owner-controlled trust roots/repositories.

Layers 1–2 may expose custom repositories through progressively clearer warnings/UX.

Official Evrosion repository remains the default trusted source when it exists.

But Evrosion must not require all software to be hosted by Evrosion.

---

## R-009.19 Side-Loading Is Permanent

There is no future rule:

> “Only App Store software may run.”

A user can deliberately install software obtained elsewhere.

Layer behavior changes the friction/warnings, not the owner's ultimate ability.

This is a direct consequence of F-002.

---

## R-009.20 Layered Installation UX

### Layer 1

- simple trusted-source defaults;
- clear identity/risk display for external package;
- package still sandboxed;
- cannot grant authority outside Layer-1 policy;
- avoids technical jargon where possible.

### Layer 2

- more details;
- explicit capability/identity information;
- deliberate override paths.

### Layer 3

- full manual package/repository control;
- warnings remain informative;
- OS does not paternalistically block deliberate owner action.

All layers preserve package signature/integrity information.

---

## R-009.21 Unsigned Packages

Unsigned/unverified development packages may exist.

System trust UI must label them accurately.

Development flow may permit:

```text
ev install --dev ./Hello.zion
```

or equivalent explicit developer mode.

Do not teach users that:

```text
unsigned = automatically malicious
```

or:

```text
signed = automatically safe
```

Signature is provenance/identity evidence.

---

## R-009.22 Official Marketplace Comes Later

0.1 does not require:

- marketplace;
- payments;
- publisher accounts;
- reviews;
- moderation backend;
- recommendation system.

E-025 explicitly excludes an application marketplace from 0.1.

The marketplace appears only when the platform has enough:

- networking;
- app stability;
- security;
- users;
- developers

to justify it.

---

## R-009.23 Marketplace Economic Rule

Carry R-001 forward:

- working target around a **10% marketplace fee**;
- not a constitutional fixed number;
- pricing may vary by economics/service costs later.

The marketplace must not fund itself through:

- forced ads;
- mandatory telemetry;
- banning alternative distribution.

---

## R-009.24 Store Review Is About Risk/Policy, Not Architectural Monopoly

Official marketplace policy may reject:

- malware;
- fraud;
- impersonation;
- deceptive packages;
- illegal content/services where required;
- packages violating marketplace rules.

But rejection from the official marketplace does not erase the owner's technical ability to sideload lawful software.

Marketplace acceptance is not equivalent to kernel permission.

---

## R-009.25 Malicious Package Response

If the official repository confirms a malicious package/version:

- stop distributing it;
- publish machine-readable advisory/status;
- warn affected installations according to Layer/security policy;
- preserve forensic/history metadata;
- revoke compromised publisher credentials where appropriate.

Do **not** silently erase user files or introduce an unaccountable remote kill switch.

Layer 3 retains deliberate owner control.

---

## R-009.26 Vulnerability vs Malicious Package

Do not treat:

```text
vulnerable package
```

and:

```text
intentionally malicious package
```

as identical.

A vulnerable package may simply need an update.

A malicious package may require delisting, key/account action and incident investigation.

Both can use R-004 advisory infrastructure.

---

## R-009.27 Dependency Model

For ordinary desktop applications, prefer:

```text
self-contained application bundle
+
stable platform contracts
```

over global shared dependency resolution.

Benefits:

- no global “dependency hell”;
- app update does not silently mutate another app;
- rollback is local;
- package is easier to reproduce;
- offline install is simpler.

Content-addressable storage may deduplicate identical bundled files internally.

---

## R-009.28 System Components Are Not Ordinary Apps

Core system software participates in System Generations and the lifecycle engine.

Do not force kernel/services/update/recovery components through the exact same dependency semantics as a third-party text editor merely for conceptual purity.

One deployment transaction system can support different artifact roles.

---

## R-009.29 App Updates Are Transactional

Application update should eventually resemble:

```text
download/verify
→ stage
→ validate
→ activate
→ retain rollback candidate as policy allows
```

A failed app update should not corrupt the old installed app.

User data remains separately durable/versioned as appropriate.

---

## R-009.30 Permission Changes on Update

When a new app version asks for materially broader authority:

```text
old:
File(selected)
Network(example.com)

new:
File(all user documents)
Microphone
Camera
```

do not silently inherit new privileges.

The owner must be informed according to Layer policy.

---

## R-009.31 Package Transparency

Package metadata should eventually expose:

- publisher identity;
- package/AppIdentity;
- version;
- content hashes;
- build/source provenance where available;
- requested capabilities;
- supported platform level;
- license;
- source location if open source;
- security advisories;
- privacy declaration where relevant.

Do not make users reverse-engineer a package to know what it asks for.

---

## R-009.32 Developer CLI

The developer experience should evolve toward commands such as:

```text
ev app new
ev app build
ev app test
ev app run
ev app package
ev app verify
ev app install
```

Exact spelling is replaceable.

Goal:

> creating the first native `.zion` app should be radically easier than learning Evrosion's internal build graph.

---

## R-009.33 SDK Contains Real Examples

Ship examples that exercise:

- basic GUI;
- file picker/grant;
- network capability later;
- background Job/service if supported;
- settings/state;
- crash reporting;
- package manifest;
- capability denial.

Examples must track the Stable SDK automatically.

Broken example code is broken platform documentation.

---

## R-009.34 Package Security Reports

The future repository should allow users/researchers to report:

- malicious package;
- typosquat;
- impersonation;
- compromised maintainer;
- suspicious update;
- vulnerability.

Serious security reports route into R-004 private disclosure where appropriate.

---

## R-009.35 Build Provenance for Packages

Encourage and later strongly prefer provenance linking package bytes to:

- source;
- revision;
- build workflow;
- builder identity.

Sigstore/SLSA-style evidence is useful.

The store should display provenance truthfully:

```text
verified provenance
publisher-signed only
unverified build
```

rather than reducing everything to one green checkmark.

---

## R-009.36 Reproducible Third-Party Packages

Reproducible builds should be encouraged but not required for every hobby application on day one.

High-trust/critical packages may later have stronger requirements.

Official Evrosion system components remain held to the stricter R-003 release standard.

---

## R-009.37 `.zion` Spec Is Open

R-006 remains authoritative:

- `.zion` interoperability spec openly implementable;
- package format is license-neutral;
- third parties may implement tools;
- no permission required to parse/create `.zion`.

Official signing/certification remains separate.

---

## R-009.38 Adversarial Findings

### Store becomes Apple-style mandatory gate
**Control:** sideloading and alternative repositories are permanent.

### Package signature becomes root permission
**Control:** signature identity is separate from runtime capabilities.

### Install script compromises OS
**Control:** declarative transactional install; no ambient-root scripts.

### Package maintainer token stolen
**Control:** scoped/short-lived publishing auth, MFA, key rotation, immutable history.

### Package deleted and name stolen
**Control:** tombstone/non-recycling/controlled transfer.

### Update silently asks for more permissions
**Control:** capability delta surfaced; no automatic grant expansion.

### Dependency update breaks unrelated apps
**Control:** application-private bundled dependencies + content deduplication.

### Official repository compromised
**Control:** TUF-like metadata roles + publisher identity + package hashes + runtime sandbox.

### Store removes package and installed copies vanish
**Control:** no silent remote file deletion.

### `.zion` becomes proprietary ecosystem lock
**Control:** open spec and third-party implementation/distribution rights.

---

## R-009.39 Locked Laws

1. `.zion` is a package format, not the official store.
2. Offline/local `.zion` installation is first-class.
3. 0.1 needs only the minimal local package flow.
4. `.zion` manifests are declarative.
5. Arbitrary ambient-root install scripts are not normal package behavior.
6. Package signatures do not grant runtime authority.
7. Capability declarations are requests, not self-grants.
8. AppIdentity remains the canonical application identity.
9. Publisher identity/signing keys remain separate from AppIdentity.
10. Published package versions are immutable.
11. Yanking is preferred over rewriting/deleting history.
12. Package identities/names are not casually recycled.
13. Future official repository uses strong MFA/scoped/short-lived publishing credentials as maturity grows.
14. Official repository preserves TUF-like anti-rollback/freeze/mix-and-match/key-compromise properties.
15. Repository metadata trust, publisher trust and runtime authority remain separate.
16. Alternative repositories are allowed.
17. Sideloading is permanently allowed.
18. Layers change UX/protection, not ultimate owner sovereignty.
19. Unsigned development packages are clearly labeled rather than falsely equated with malware.
20. Marketplace is not a 0.1 requirement.
21. Marketplace fee target remains approximately 10%, not constitutionally fixed.
22. Store policy may reject malware/fraud but cannot become the only way software runs.
23. Malicious package response does not create a hidden remote file-deletion power.
24. App-private bundled dependencies are preferred for normal apps.
25. System components remain integrated with System Generation lifecycle.
26. App updates become transactional/rollback-aware.
27. Capability expansion on update is surfaced and not silently granted.
28. Package metadata/provenance should be inspectable.
29. Developer tooling should make `.zion` creation/testing simple.
30. `.zion` specification remains open and independently implementable.

---

# R-010 — DOCUMENTATION, ARCHITECTURE MEMORY & KNOWLEDGE PRESERVATION

## R-010.1 Purpose

Evrosion is already large enough that project memory can become a technical risk.

The biggest long-term danger is not merely losing a Markdown file.

It is losing:

> **why a boundary exists**

and then having a future developer/AI “simplify” it back into the exact failure mode the architecture was designed to prevent.

R-010 makes knowledge a maintained system.

---

## R-010.2 Docs as Code

Canonical technical/project documentation lives in version control near the code.

Primary format:

```text
Markdown
```

unless another source format is clearly better for a specific generated reference.

Do not make Notion, chat logs, Discord, a private notebook or an AI conversation the canonical architecture database.

Those may be working surfaces.

Git is canonical.

---

## R-010.3 One Master Index, Many Focused Documents

Do not create one ever-growing 500,000-line “master plan” as the only source.

Use:

```text
docs/INDEX.md
```

or equivalent as the master map.

Then focused documents.

This superfile is an ingestion/decision packet.

The repository should split concepts so humans and AI tools can load only what they need.

---

## R-010.4 Proposed Documentation Hierarchy

Conceptual structure:

```text
docs/
  INDEX.md
  status/
    PROJECT_STATUS.md
    ROADMAP.md

  foundation/
    F-001...
    principles.md
    glossary.md

  architecture/
    E-001...
    E-026...
    invariants.md
    exception-register.md

  decisions/
    ADR-0001...
    ADR-0002...

  release-policy/
    R-001...
    R-011...

  specs/
    contracts/
    platform-api/
    zion/
    boot/
    package/
    state/

  developer/
    tutorials/
    how-to/
    reference/
    explanation/

  operations/
    release-runbook.md
    backup-restore.md
    security-response.md

  generated/
    api/
    schemas/
```

Exact paths can differ.

The separation of concerns should not.

---

## R-010.5 Document Status Header

Canonical decision/spec documents should state status.

Recommended vocabulary:

```text
DRAFT
PROPOSED
ACCEPTED
IMPLEMENTING
IMPLEMENTED
DEPRECATED
SUPERSEDED
ARCHIVED
```

Also include:

- identifier;
- title;
- last meaningful revision;
- supersedes/superseded-by where applicable.

Avoid mystery files whose authority cannot be determined.

---

## R-010.6 Decision Hierarchy

When documents appear to conflict, use an explicit hierarchy.

Conceptual order:

```text
Foundational laws / constitutional governance
↓
accepted architecture laws (E-series)
↓
accepted release/project laws (R-series)
↓
accepted ADRs/amendments
↓
versioned interface/spec contracts
↓
current implementation/tests
↓
tutorials/explanations/examples
```

Important nuance:

- code/tests define what the current implementation actually does;
- higher-level accepted laws define what the implementation is supposed to preserve.

A mismatch is **architecture drift**, not an excuse to pretend one side does not exist.

---

## R-010.7 Implementation Evidence May Trigger Change

E-001–E-026 are not religious scripture.

If implementation proves a real architectural contradiction or unacceptable cost:

```text
evidence
→ issue/design note
→ ADR/amendment
→ review
→ update canonical law
→ implementation change
```

Never:

```text
maintainers changed it
→ therefore the architecture changed
```

---

## R-010.8 ADRs Preserve Why

Use Architecture Decision Records for meaningful implementation/architecture decisions.

An ADR captures:

- context/problem;
- decision;
- rationale;
- alternatives;
- consequences;
- status;
- related requirements/tests;
- supersession.

The ADR community describes an ADR as a record of one architecturally significant decision and its rationale.

The reason matters as much as the final answer.

---

## R-010.9 ADRs Are Append-Or-Supersede, Not History Rewrites

If a decision changes:

```text
ADR-0012 — Accepted
ADR-0047 — Supersedes ADR-0012
```

Do not silently edit old history until it appears the project always believed the new thing.

Living summary docs may be updated.

Historical decisions remain inspectable.

---

## R-010.10 Canonical Glossary

Maintain one glossary for terms such as:

```text
Job
Capability
Root Supervisor
AppIdentity
System Generation
Known Good
Platform API Level
Trusted Control
Layer 1/2/3
Official Evrosion
Evrosion Certified
.zion
```

New terms should not be invented casually when an existing concept already exists.

AI systems especially benefit from canonical vocabulary.

---

## R-010.11 Requirements and Invariants Have IDs

Keep stable identifiers.

Examples:

```text
F-002
E-009
R-004
AF-009
```

Tests and implementation comments can refer to IDs.

This creates traceability:

```text
principle
→ architecture
→ contract
→ code
→ test
```

---

## R-010.12 Architecture Fitness Tests Are Documentation

A test proving:

```text
process cannot forge capability
```

is executable documentation.

A test proving:

```text
broken System Generation rolls back
```

is stronger than a paragraph claiming rollback exists.

Where practical, each major invariant has:

- human explanation;
- executable test;
- implementation link.

---

## R-010.13 Documentation Changes Travel With Code

A PR changing a Stable/public behavior should update the relevant documentation in the same change whenever practical.

Do not accumulate:

```text
implementation today
documentation six months later
```

as normal process.

CI can detect some drift through generated schemas/reference.

Human review handles semantics.

---

## R-010.14 Use Generated Reference Where Possible

Reference material that can be mechanically generated from:

- IDL;
- schemas;
- CLI definitions;
- package manifests;
- API annotations

should be generated.

Diátaxis correctly emphasizes that reference docs need accurate, authoritative description; code/schema generation helps prevent drift.

Generated reference does **not** replace explanation/tutorials.

---

## R-010.15 Documentation Types

Use the Diátaxis distinction as a practical organizing guide:

```text
Tutorial     — help someone learn
How-to       — help someone accomplish a task
Reference    — exact facts/interfaces
Explanation — help someone understand why/how
```

Do not bury a newcomer tutorial inside an API reference or turn every reference page into an essay.

---

## R-010.16 Developer Onboarding Path

A new contributor should have an explicit reading/build path.

Example:

```text
README
→ START_HERE
→ build/run Evrosion
→ project map
→ architecture invariants
→ subsystem docs
→ first issue
```

Do not require reading E-001 through E-026 before someone can fix a small test.

Load detail progressively.

---

## R-010.17 Technical summaries

Concise subsystem maps may link relevant invariants, contracts, ADRs and test
commands. They assist navigation and must identify their actual source versions.

## R-010.18 Derived summaries are not canonical

Summaries cannot outrank their sources. Stale summaries must be reconciled or
clearly identified; maintain one usable technical index rather than conflicting
copies of the architecture.

---

## R-010.19 Decisions must enter version control

Before a decision becomes canonical, record it in the applicable versioned
requirement, ADR or specification. Private conversations are not durable project
governance.

## R-010.20 Visible review and history

Architecture and documentation changes require visible diffs and review. Do not
silently delete constraints, simplify foundational guarantees without a decision,
or create a competing glossary. Preserve accepted technical rationale and record
supersession explicitly.

---

## R-010.21 Supersession Registry

Maintain machine-readable or easily parsed supersession metadata.

Examples:

```text
.sion → .zion
ADR-0047 supersedes ADR-0012
R-008 replaces prior informal support wording
```

This prevents an AI/search result from treating stale terminology as current authority.

---

## R-010.22 `.sion` → `.zion` Documentation Cleanup

Current canonical extension:

```text
.zion
```

Action:

- living docs use `.zion`;
- source code uses `.zion`;
- tests use `.zion`;
- new examples use `.zion`;
- glossary defines `.zion`;
- older archived docs may retain `.sion` with clear supersession annotation.

Do not create compatibility for `.sion` solely because an old planning document contains the old spelling.

---

## R-010.23 Diagrams Are Source-Controlled

Prefer diagram source that can be diffed:

```text
Mermaid
Graphviz/DOT
PlantUML
ASCII where sufficient
```

Rendered PNG/SVG may be generated.

Do not make the only architecture description an opaque image.

---

## R-010.24 Runbooks

Critical operational tasks need runbooks before they become scary.

Eventually maintain:

- release;
- key rotation;
- signing compromise;
- backup restore;
- repository compromise;
- CVE/advisory;
- package takedown;
- Foundation/company continuity;
- incident response.

R-003/R-004 define policy.

Runbooks define execution.

---

## R-010.25 Release Documentation Is Versioned

A release should preserve the documentation that matched it.

Current docs may evolve.

But someone debugging Evrosion 0.4 should be able to determine what 0.4's API/configuration meant.

Tag/release documentation with source.

Do not make the latest docs the only surviving explanation of old releases.

---

## R-010.26 Documentation Tests

Where valuable:

- link checking;
- code-snippet compilation;
- schema examples;
- CLI examples;
- `ev` command smoke tests;
- glossary reference checks;
- duplicate ID detection;
- stale generated-doc detection.

A tutorial containing commands that no longer run is a failing test in prose form.

---

## R-010.27 Knowledge Preservation / Bus Factor

For every mature critical subsystem, documentation should eventually answer:

- what it owns;
- trust boundary;
- major data structures;
- startup/lifecycle;
- failure behavior;
- important invariants;
- debugging entry points;
- tests;
- known debt;
- current maintainer(s).

This prevents knowledge from existing only inside one person's head.

---

## R-010.28 Technical Debt Register

Do not hide known shortcuts in comments nobody sees.

Maintain explicit debt/exception records for things that intentionally violate preferred architecture temporarily.

Each entry needs:

- reason;
- owner;
- scope;
- risk;
- removal trigger;
- expiry/review point.

PRE-M0 already established this principle.

---

## R-010.29 Project Status Is Not Architecture

Maintain a small current-state file such as:

```text
docs/status/PROJECT_STATUS.md
```

containing:

- current milestone;
- what works;
- what is broken;
- immediate work;
- known blockers.

This file changes frequently.

It must not be confused with stable architectural law.

---

## R-010.30 Master Tracker

The user wants a living master tracker.

Implement it as an **index/status surface**, not as duplicated canonical content.

It should link to:

- active milestone;
- completed E/R decisions;
- open ADRs;
- current implementation slices;
- current blockers;
- next work.

Do not copy every entire design into it.

---

## R-010.31 Backups Apply to Knowledge Too

R-007 backup policy covers documentation because docs are in Git.

Non-Git external evidence that matters—legal agreements, signed releases, audit reports—must also have explicit archival storage later.

---

## R-010.32 Adversarial Findings

### AI receives old `.sion` doc and implements wrong extension
**Control:** supersession registry + canonical glossary + living-doc migration.

### Architecture exists only in giant handoff file
**Control:** master index + focused canonical docs.

### Code drifts while docs remain pretty
**Control:** docs in PR + generated reference + fitness tests.

### Future maintainer knows what but not why
**Control:** ADRs preserve rationale/tradeoffs.

### Chat history becomes project database
**Control:** repository is canonical memory boundary.

### AI summary contradicts source
**Control:** context packs derived/stamped and non-authoritative.

### Old decision is rewritten to hide history
**Control:** supersede, don't erase.

### New contributor must read 2,000 pages first
**Control:** progressive onboarding and layered documentation.

---

## R-010.33 Locked Laws

1. Canonical project documentation is version-controlled with the code.
2. Markdown is the default human-authored source format.
3. GitHub/chat/Notion are not separate canonical architecture databases.
4. Use one master index with focused documents, not one giant permanent source file.
5. Canonical docs carry explicit status/identity.
6. Document authority/precedence is explicit.
7. Implementation conflict with architecture triggers drift handling, not silent reinterpretation.
8. Architecturally significant changes use ADRs/amendments.
9. Superseded decisions remain historically visible.
10. Maintain one canonical glossary.
11. Requirements/invariants keep stable IDs.
12. Fitness tests are part of architectural documentation.
13. Behavior changes update docs with code where practical.
14. Generate technical reference from schemas/IDL/code where appropriate.
15. Organize docs around tutorial/how-to/reference/explanation needs.
16. Maintain a progressive new-contributor path.
17. Maintain AI context packs for major work areas.
18. AI context packs are derived and never canonical.
19. Decisions from AI/chat become canonical only after repository documentation.
20. AI tools must not silently rewrite accepted architecture.
21. Maintain explicit supersession metadata.
22. `.zion` supersedes historical `.sion` naming.
23. Diagrams retain source-controlled editable representation.
24. Critical operational procedures eventually receive runbooks.
25. Release-era documentation remains recoverable/versioned.
26. Documentation gets automated checks where useful.
27. Critical subsystems document enough knowledge to reduce bus factor.
28. Temporary shortcuts live in a visible exception/debt register.
29. Project status/roadmap is separate from stable architecture.
30. The living master tracker links to canonical material rather than duplicating it.

---

# R-011 — M0 PUBLIC GATE & EVROSION 0.1 DEVELOPER PREVIEW READINESS

## R-011.1 Purpose

Evrosion is approaching its first bootable instance.

That makes “done” definitions urgent.

R-011 separates three different milestones:

```text
A. M0 ENGINEERING COMPLETE
B. PUBLIC M0 READY
C. EVROSION 0.1 DEVELOPER PREVIEW READY
```

They are not the same thing.

---

## R-011.2 Canonical Initial Scope

E-025 remains the authority for the 0.1 scope.

Its central philosophy:

> **Architecture-complete, feature-minimal. Prove the spine before building the body.**

Primary initial target:

```text
CPU: x86-64
Firmware: UEFI
Reference machine: QEMU/KVM
Host build environment: conventional Linux acceptable
```

0.1 is a development/bringup system, not a consumer daily driver.

---

## R-011.3 M0 Engineering Goal

M0 proves the reproducible toolchain/boot loop.

Existing PRE-M0 direction includes:

```text
ev bootstrap
ev build
ev run
ev debug kernel
```

and:

- x86-64;
- UEFI;
- QEMU;
- serial output;
- panic output;
- symbolized debugging;
- framebuffer handoff;
- repeatable image generation.

A tiny first boot message is enough to prove entry into the real kernel.

Do not pull Root Supervisor/service graph work into M0.

That begins later.

---

## R-011.4 M0 Engineering Exit Gate

M0 is complete only when all applicable items below are demonstrated, not merely implemented somewhere.

### Build

- pinned supported toolchain resolves;
- clean checkout can bootstrap;
- clean build succeeds;
- image generation succeeds repeatedly;
- build identity includes source revision/build information.

### Boot

- UEFI/QEMU launches the real artifact;
- control reaches Evrosion kernel code;
- expected serial boot signature appears;
- failure/panic output is usable.

### Debug

- `ev debug kernel` or its accepted equivalent works;
- symbols resolve meaningfully;
- developer can locate a fault/panic.

### Display handoff

- framebuffer/initial display boot information is captured as required by the M0 plan;
- no premature compositor requirement.

### Reproducibility

- two clean build locations can be compared;
- known remaining nondeterminism is documented rather than ignored.

### Test

- M0-specific architecture fitness tests pass;
- temporary exceptions are registered with expiry/removal trigger.

---

## R-011.5 M0 Non-Goals

M0 is **not** blocked by absence of:

- scheduler sophistication;
- Root Supervisor;
- full capability system;
- filesystem;
- networking;
- graphical shell;
- app runtime;
- `.zion`;
- real hardware;
- marketplace;
- AI;
- compatibility;
- audio.

If those sneak into the M0 critical path without foundational necessity:

> scope creep has won.

---

## R-011.6 M0 Complete Does Not Automatically Mean Public

After the engineering gate passes, perform a separate public-repository gate.

This prevents:

```text
“Holy shit, it booted”
→ immediately expose dirty repository/history/secrets
```

---

## R-011.7 Public M0 Gate — Legal

Before public visibility:

- R-006 licenses applied consistently enough to avoid false claims;
- top-level multi-license explanation exists;
- third-party code provenance/license audit completed for current code;
- no known copied incompatible code;
- `LICENSES/`/notices structure exists as appropriate.

If final ECA legal text is not ready:

> repository may be public, but CONTRIBUTING must state that substantial external code contributions are temporarily not mergeable until the ECA process is active.

Public source visibility and accepting copyright rights are separate decisions.

---

## R-011.8 Public M0 Gate — Security Hygiene

Required:

- Git history secret scan;
- revoke any exposed secrets;
- no private signing keys;
- no private API tokens;
- no personal/private files unintentionally committed;
- `SECURITY.md`;
- private reporting path;
- public repo security scanning enabled where available.

---

## R-011.9 Public M0 Gate — GitHub Configuration

Required:

- official Evrosion GitHub organization;
- canonical repository;
- `main` protection/ruleset;
- force-push/delete protection;
- CI checks;
- issue templates/forms;
- PR template;
- Discussions;
- repository topics/description;
- Releases configured;
- strong founder account authentication/recovery.

Do not wait for an expensive GitHub plan if public Free features meet the current need.

---

## R-011.10 Public M0 Gate — Documentation

A stranger must be able to answer:

```text
What is Evrosion?
What currently works?
What definitely does not work?
How do I build it?
How do I boot it?
What host environment is supported?
How do I debug it?
How do I report a bug?
How do I report a security bug?
How do I contribute?
```

without messaging the founder privately.

---

## R-011.11 Public M0 Gate — Repository Honesty

README top section must state something equivalent to:

```text
EARLY DEVELOPMENT

Evrosion currently targets x86-64 UEFI under QEMU/KVM.
It is not a daily-driver operating system.
Current milestone: M0 / early bring-up.
```

Do not feature future architecture as if already implemented.

Use separate sections:

```text
Implemented
In progress
Designed / planned
Not in 0.1 scope
```

---

## R-011.12 Public M0 Launch Style

M0 public opening should be relatively quiet/technical.

Goal:

> allow technically interested people to see a real project and follow it.

Do not burn the major public launch moment on:

```text
kernel prints one line
```

Selective OS-development outreach is fine.

The major recruitment push comes at 0.1 when the architectural demonstration is compelling.

---

## R-011.13 M1–M5 Remain Evidence Milestones

Carry the E-025 map:

```text
M0 — Toolchain & Boot
M1 — Kernel Spine
M2 — Capability Userspace
M3 — Persistent Machine
M4 — Graphical Evrosion
M5 — Native Platform Slice
      ↓
Evrosion 0.1
```

M6 begins the connected developer-alpha expansion after 0.1.

---

## R-011.14 M1 Proof

M1 should prove the kernel spine:

- memory primitives;
- kernel object model;
- capabilities;
- derivation/revocation;
- threads;
- minimal scheduling;
- IPC primitive;
- fault/exception delivery;
- Job skeleton/resource attribution.

Do not evaluate M1 by lines of code.

Evaluate it by invariant tests.

---

## R-011.15 M2 Proof

M2 proves capability-native userspace:

- Root Supervisor;
- Job hierarchy;
- userspace services;
- typed IPC;
- service failure containment;
- authority custody/restart semantics.

Critical proof:

> crashing/restarting a service does not duplicate or leak authority.

---

## R-011.16 M3 Proof

M3 proves the persistent machine:

- block/storage path;
- durable operations;
- System Generations;
- journal/recovery semantics;
- Known Good;
- health-gated activation;
- rollback.

Power-loss/fault injection begins here.

Expected durable result:

```text
old committed state
OR
new committed state
```

not half-state corruption.

---

## R-011.17 M4 Proof

M4 proves graphical Evrosion:

- display/surface path;
- basic compositor;
- input;
- text;
- shell;
- launch native graphical app;
- focus/render;
- trusted file picker/grant;
- crash app;
- shell survives;
- relaunch succeeds.

Fancy animation/GPU acceleration does not block M4.

---

## R-011.18 M5 / 0.1 Proof

M5 is the Evrosion 0.1 completion milestone.

It proves the minimal coherent native platform.

Required conceptually:

- AppIdentity;
- minimal `.zion`;
- launcher/install/development deployment;
- capability-mediated file grant;
- structured diagnostics;
- app lifecycle;
- basic Job metrics/resource accounting;
- failure/restart;
- provider-replacement proof where required by E-025;
- System Generation rollback proof.

---

## R-011.19 Canonical 0.1 Demonstration

The strongest 0.1 acceptance test should be one recorded end-to-end run:

```text
UEFI/QEMU
→ Evrosion kernel
→ Initial Root Authority
→ Root Supervisor
→ userspace services
→ capability-routed typed IPC
→ persistent storage
→ graphical shell/input
→ launch Hello.zion
→ Open File
→ trusted picker
→ select one file
→ scoped capability delivered
→ app accesses only selected file
→ press Crash Me
→ app dies
→ shell/system survives
→ structured crash record exists
→ app relaunches
→ activate deliberately broken System Generation
→ health gate fails
→ rollback to Known Good
→ system returns healthy
```

If this works genuinely under the real architecture:

> Evrosion 0.1 exists.

---

## R-011.20 0.1 Definition of Success

Carry E-025's existing success concept, updated for current naming:

> **A native graphical Evrosion application packaged as `.zion` can boot under the real capability/service/storage/display architecture, receive access only to a user-selected file, crash without killing the system, produce structured diagnostics, restart, and continue running on a system that can roll back from a deliberately broken System Generation.**

That sentence remains the 0.1 north star.

---

## R-011.21 0.1 Security Gate

Required before formal 0.1:

- capability enforcement works for tested boundaries;
- process isolation works;
- explicit delegation works;
- Root Supervisor trust/authority behavior matches architecture;
- `.zion` content/integrity validation exists at the required minimal level;
- malformed/unauthorized access tests fail safely;
- no known Critical/High security regression that invalidates the demonstrated trust model.

R-004 remains authoritative.

---

## R-011.22 0.1 Recovery Gate

Required:

- Known Good generation;
- health gate;
- deliberate failed generation;
- automatic/defined rollback behavior;
- basic recovery interface/path;
- recovery path does not depend on the failed normal generation being healthy.

A rollback diagram is not acceptance.

The rollback must be executed.

---

## R-011.23 0.1 Diagnostics Gate

Required:

- serial logs;
- structured basic events;
- kernel panic record where applicable;
- app crash record;
- build ID;
- System Generation identity;
- enough state inspection to debug the demonstration.

Full distributed tracing/replay is later.

---

## R-011.24 0.1 Negative Tests

The release candidate must prove that forbidden behavior fails.

Examples:

- app attempts ungranted file access → denied;
- invalid capability → rejected;
- revoked capability → fails;
- malformed IPC → contained;
- app crash → system survives;
- selected service crash → contained/recoverable;
- invalid `.zion` hash/content → rejected;
- incompatible package format → clear rejection;
- broken generation → rollback;
- corrupted/partial durable transaction → old or new committed state, not half state where applicable.

Security exists in denied paths.

---

## R-011.25 0.1 Reproducibility/Provenance Gate

Before official GitHub Release:

- exact source commit identified;
- clean build recipe recorded;
- toolchain pinned;
- release image hash recorded;
- SBOM/provenance generated to the maturity available;
- official/developer-preview signing applied under R-003;
- independent rebuild comparison attempted/documented.

A Developer Preview still deserves authentic artifacts.

---

## R-011.26 0.1 Documentation Gate

Required:

- README current;
- build/run quickstart tested on a fresh supported Linux host;
- debugger instructions;
- architecture overview;
- 0.1 limitations;
- `.zion` minimal developer guide;
- security-reporting instructions;
- known issues;
- release notes;
- contribution guide.

The quickstart should be tested by following it literally from a clean environment.

---

## R-011.27 0.1 Community Gate

Before the major 0.1 outreach push:

- GitHub Discussions usable;
- issue forms usable;
- first help-wanted areas identified;
- contributor/legal path clear;
- AI contribution policy visible;
- maintainers know how to triage duplicates/security reports;
- short demo recorded;
- release text answers R-005's five questions.

Do not invite hundreds of people into a repository where nobody knows how to report a bug.

---

## R-011.28 0.1 Performance Gate

Do not turn 0.1 into a benchmark contest.

But record baseline measurements:

- boot duration;
- image size;
- kernel/system memory footprint;
- IPC microbenchmark;
- app launch time where relevant;
- frame latency/basic responsiveness.

The purpose is regression tracking.

No arbitrary “must beat Linux” requirement.

---

## R-011.29 0.1 Scope Exclusions

The following do **not** block 0.1:

```text
Wi-Fi
Bluetooth
audio
GPU acceleration
broad real-hardware support
Windows compatibility
Linux compatibility
AI assistant
cloud services
marketplace
OEM readiness
enterprise deployment
gaming compatibility
mobile support
consumer installer polish
website
perfect animations
huge native app ecosystem
self-hosted Evrosion build environment
```

Do not allow excitement to drag these into M5.

---

## R-011.30 Real Hardware

Real hardware experimentation may begin whenever useful.

But:

> 0.1 success does not require real PC support.

QEMU is the first reference computer.

A real machine boot before 0.1 is a bonus/data point, not a reason to redesign the release gate.

---

## R-011.31 Networking

Networking belongs after the 0.1 architecture proof unless implementation evidence shows an unavoidable prerequisite.

0.1 must remain usable/demoable offline.

M6 can begin the connected workstation/developer alpha.

---

## R-011.32 AI

AI is explicitly non-blocking for 0.1.

Do not add an AI assistant merely because Evrosion is meant to support AI later.

Deterministic authority/recovery must work first.

---

## R-011.33 Compatibility

Windows/Linux compatibility is explicitly non-blocking for 0.1.

Native lifecycle must be coherent before compatibility runtimes are allowed to shape the platform.

---

## R-011.34 Website

No website blocks M0 or 0.1.

R-005 remains:

```text
GitHub = public Evrosion HQ until approximately 0.9
```

---

## R-011.35 Release Name

Formal first release:

> **Evrosion 0.1 — Developer Preview**

Do not call it Stable consumer release.

It may be Official in authenticity/origin while still being a Developer Preview in maturity.

---

## R-011.36 Release Page Header

Recommended structure:

```text
Evrosion 0.1 — Developer Preview

For:
developers, researchers, contributors, technical enthusiasts

Primary target:
x86-64 + UEFI + QEMU/KVM

Not for:
daily-driver use or important production data

This release proves:
<short architecture proof>
```

Then:

- what works;
- what does not;
- how to run;
- known issues;
- hashes/signatures/provenance;
- source commit;
- report/contribute links.

---

## R-011.37 Formal Readiness Record

Create a release evidence file such as:

```text
release/readiness/0.1.md
```

containing:

- candidate commit;
- exact build identity;
- checklist;
- test links/results;
- known exceptions;
- reproducibility evidence;
- SBOM/provenance refs;
- unresolved known issues;
- founder release decision.

This turns “I think we're ready” into an auditable record.

---

## R-011.38 Founder Release Authority

During founder era:

- founder is final release authority under R-002;
- automated evidence informs the decision;
- serious security gate under R-004 cannot be dismissed merely for schedule/marketing convenience.

The founder may decide:

```text
NO RELEASE
```

even if CI is green.

CI may also prove:

```text
DO NOT RELEASE
```

when a hard gate fails.

---

## R-011.39 Broken 0.1 After Publication

If a formal 0.1 artifact is wrong:

do not silently replace it.

Use:

```text
0.1.1
```

or an explicitly new System Generation/release identity.

R-003/R-005 immutability applies.

---

## R-011.40 Post-0.1 Triage

The first public attention wave should be treated as an engineering input.

Track:

- build failures;
- unclear docs;
- architecture misunderstandings;
- repeated environment problems;
- contribution friction;
- security reports;
- QEMU failures;
- interesting external use cases.

Do not immediately change architecture based on one comment.

Look for repeated evidence.

---

## R-011.41 0.1 Success Metrics

Primary:

- canonical acceptance sequence works;
- independent people can build/run;
- no trust/recovery invariant is faked;
- first recurring contributors appear;
- useful bug/security reports arrive.

Secondary:

- stars;
- social traffic;
- raw downloads.

Do not optimize the OS around GitHub-star velocity.

---

## R-011.42 Scope-Creep Test

Before adding something to 0.1 critical path, ask E-025's existing questions:

```text
Does this prove a foundational invariant?

Does this unlock the next required vertical slice?

Would delaying it create expensive architectural debt?
```

If no:

```text
move it later
```

---

## R-011.43 Adversarial Findings

### First boot happens and repo is instantly published dirty
**Control:** separate Public M0 Gate.

### M0 turns into userspace architecture work
**Control:** hard M0 non-goals.

### 0.1 waits for Wi-Fi/NVIDIA/audio
**Control:** explicit QEMU-first scope exclusions.

### Beautiful demo uses fake authority shortcuts
**Control:** acceptance path must use real capability/storage/recovery architecture.

### App crash kills shell
**Control:** 0.1 blocked.

### Broken generation cannot roll back
**Control:** 0.1 blocked.

### Build only works on founder's machine
**Control:** fresh-host quickstart/reproducibility gate.

### Release contains secret or incompatible copied code
**Control:** public/legal/security gates before publication.

### Early contributors create licensing mess
**Control:** substantial merges wait for R-006 ECA path.

### `.sion` and `.zion` both appear and maintainers implements both
**Control:** `.zion` canonical supersession rule.

### Marketing calls 0.1 daily-driver OS
**Control:** Developer Preview name/limitations mandatory.

---

## R-011.44 Locked Laws

1. M0 Engineering Complete, Public M0 Ready and 0.1 Ready are separate gates.
2. E-025 remains the canonical initial-scope authority.
3. M0 proves build/boot/debug/reproducibility, not the full OS.
4. M0 scope must not absorb M1+ systems without foundational necessity.
5. Public repo does not open merely because the first boot worked.
6. Public M0 requires legal/license hygiene.
7. Public M0 requires history/secret hygiene.
8. Public M0 requires GitHub protections and security policy.
9. Public M0 requires usable stranger-facing build/run docs.
10. M0 public opening is technical/quiet; 0.1 is the larger developer recruitment moment.
11. M1 proves kernel spine.
12. M2 proves capability-native userspace/supervision.
13. M3 proves persistence/System Generations/rollback.
14. M4 proves graphical shell/app/file grant/crash containment.
15. M5 completes Evrosion 0.1.
16. The canonical 0.1 demo uses the real architecture end-to-end.
17. `.zion` is the package name used in the 0.1 acceptance path.
18. 0.1 security boundaries require negative tests.
19. 0.1 rollback must be executed, not merely specified.
20. 0.1 diagnostics must identify build/app/generation sufficiently to debug failures.
21. Official 0.1 artifacts carry source identity/hash/signing/provenance appropriate to maturity.
22. 0.1 documentation is tested from a fresh supported host.
23. Community intake exists before major 0.1 outreach.
24. Performance is measured for regression, not optimized into architectural corruption.
25. Networking, broad hardware, compatibility, AI, marketplace, website and consumer polish do not block 0.1.
26. QEMU/KVM remains the 0.1 reference target.
27. Formal release name is Evrosion 0.1 — Developer Preview.
28. Every release keeps a readiness/evidence record.
29. Published 0.1 artifacts are immutable; fixes get new identity.
30. Post-launch feedback is evidence, not automatic architecture authority.

---

# 2. CROSS-R IMPLEMENTATION ORDER

maintainers should not try to fully implement R-007 through R-011 at once.

Use this order.

## NOW — while M0 is finishing

```text
R-010:
- docs index
- canonical glossary
- supersession note .sion → .zion
- ADR directory/template
- project status file

R-007:
- CI basics
- pinned Action revisions
- least-privilege workflow permissions
- secret scan
- dependency/license checks
- backup script/runbook skeleton

R-011:
- M0 engineering checklist
- capture first successful boot revision
- reproducibility check
- fresh-host bootstrap check
```

## AFTER M0 PASSES — before public repo

```text
R-006/R-011:
- apply license layout
- audit third-party provenance
- legal contribution status visible

R-005/R-007:
- GitHub organization
- README
- CONTRIBUTING
- SECURITY
- CODE_OF_CONDUCT
- issue forms / PR template
- Discussions
- repository topics
- branch/ruleset protections

R-007:
- CodeQL
- secret scanning
- dependency review
- external backup
```

## M1–M4

```text
R-008:
- mark all APIs Internal/Experimental by default
- begin explicit contract version metadata
- add compatibility fixture structure

R-010:
- link invariants to fitness tests
- generate component docs/context packs

R-007:
- add QEMU integration lane
- performance baseline tracking
- fault injection as relevant
```

## M5 / 0.1

```text
R-009:
- minimal .zion manifest
- integrity verification
- local/offline install
- capability requests
- developer package tooling

R-011:
- canonical full demonstration
- negative tests
- rollback proof
- release evidence record

R-003/R-007:
- source revision
- hashes
- SBOM
- provenance
- signatures
- immutable GitHub release where appropriate
```

## AFTER 0.1

```text
R-009:
- network repository design
- publisher identities
- OIDC trusted publisher path
- TUF-like metadata
- package advisories

R-008:
- begin explicit stable Platform API promotion based on real usage

M6:
- networking
- update fetch
- remote tooling
- first real-PC slice
```

Marketplace/payment infrastructure remains later.

---

# 3. IMPLEMENTATION AND RELEASE BOUNDARIES

Do not:

- split the OS into many repositories immediately;
- create a website before ~0.9 merely because this document mentions future web infrastructure;
- implement a marketplace for 0.1;
- implement networking because package repositories are described here;
- implement `.sion` compatibility as a separate format;
- use package signatures as capability grants;
- add root install scripts;
- promise a permanent kernel module ABI;
- mark current prototype APIs Stable automatically;
- invent an exact ten-year compatibility guarantee;
- choose an exact EU commercial support period before commercial product/legal analysis;
- add Linux GPL-2.0-only source code to the GPLv3-only core;
- create binding CLA/commercial/trademark legal text without counsel;
- store Official release root keys as ordinary GitHub secrets;
- execute arbitrary fork code on privileged persistent runners;
- turn GitHub into Evrosion's only backup;
- treat derived summaries as canonical architecture;
- block 0.1 on real hardware, AI, networking, gaming, audio or marketplace;
- “fix” a failed release by replacing the bytes under the same release identity.

---

# 4. DEFERRED QUESTIONS — DELIBERATELY NOT INVENTED

These remain later evidence/legal/financial decisions:

## R-007

- exact backup provider;
- exact backup frequency at each scale;
- exact number/timing of backup org owners;
- exact CI runner fleet;
- exact SLSA target level/date;
- exact hardware-key/signing implementation.

## R-008

- exact number of Stable Platform API levels simultaneously supported;
- exact time duration of app compatibility;
- exact commercial support periods;
- exact hardware support duration;
- exact criteria for “Supported” vs “Certified” per device category.

## R-009

- exact marketplace launch version;
- exact marketplace fee at launch;
- package namespace syntax;
- exact publisher account-recovery process;
- exact signing algorithms;
- exact TUF-like metadata encoding;
- whether/when reproducible builds become mandatory for selected package classes.

## R-010

- exact documentation generator;
- exact static-site engine at/after 0.9;
- exact context-pack generator;
- exact diagram tooling.

## R-011

- exact date of M0 public opening;
- exact date of 0.1;
- arbitrary performance numbers;
- real-hardware targets before M6.

These are not omissions.

They are intentionally postponed because choosing them now would create fake precision.

---

# 5. 2026 RESEARCH BASIS

The following external sources were checked while producing R-007 through R-011.

## GitHub repository/security operations

**GitHub repository rulesets / protected branches**

Public repositories on GitHub Free / Free for organizations can use repository rulesets and protected branches, including controls around pushes, deletion, required status checks and pull requests.

https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets

https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

**GitHub secure Actions use**

GitHub currently recommends pinning third-party Actions to full-length commit SHAs for immutable consumption and applying least privilege to workflow credentials.

https://docs.github.com/en/actions/reference/security/secure-use

https://docs.github.com/en/actions/tutorials/authenticate-with-github_token

**GitHub OIDC**

GitHub supports OIDC so workflows can obtain short-lived cloud credentials rather than storing long-lived secrets.

https://docs.github.com/en/actions/concepts/security/openid-connect

**GitHub 2FA**

Organizations can require 2FA and secure methods for members/collaborators.

https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization

**GitHub CodeQL**

GitHub CodeQL currently supports Rust and can run code scanning on public repositories.

https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning

**GitHub secret scanning**

Secret scanning can examine repository history for exposed credentials and is available to public repositories.

https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning

**GitHub dependency review**

Dependency review shows dependency changes and vulnerability/license information in PRs.

https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review

**GitHub backups**

GitHub documents mirror clones and migration/archive approaches for repository backup.

https://docs.github.com/en/repositories/archiving-a-github-repository/backing-up-a-repository

**GitHub artifact attestations**

GitHub can produce cryptographically signed artifact provenance linked to workflow/repository/commit identity.

https://docs.github.com/en/actions/concepts/security/artifact-attestations

---

## OpenSSF repository security

OpenSSF's SCM configuration guidance emphasizes:

- limited privileged owners/admins;
- 2FA;
- restrictive default permissions;
- branch protection/review;
- minimal workflow permissions;
- security scanning;
- auditing.

https://best.openssf.org/SCM-BestPractices/github/

https://openssf.org/scorecard/

---

## SLSA

SLSA 1.2 is the current approved specification at the time of this document.

It defines Build maturity including:

```text
L1 provenance exists
L2 signed provenance from hosted platform
L3 hardened build platform
```

https://slsa.dev/spec/v1.2/build-track-basics

https://slsa.dev/spec/v1.2/provenance

---

## TUF

The Update Framework's current specification is designed to defend software-update systems from classes including:

- arbitrary installation;
- rollback;
- freeze;
- mix-and-match;
- malicious mirrors;
- key compromise.

It separates root, targets, snapshot and timestamp roles and supports threshold trust.

https://theupdateframework.io/specification/latest/

---

## OpenSSF package repository security

OpenSSF's package repository security principles recommend increasing maturity around:

- MFA;
- phishing-resistant auth;
- scoped tokens;
- OIDC trusted publishers;
- immutable/yanked versions;
- typosquat defense;
- malicious-package reporting;
- vulnerability warnings;
- provenance;
- SBOM support.

https://repos.openssf.org/principles-for-package-repository-security.html

---

## Sigstore

Sigstore provides identity-based artifact signing, short-lived certificates and public transparency logging concepts useful for future package/release provenance.

https://docs.sigstore.dev/

---

## SPDX

SPDX is an international standard for software component/license/SBOM information. SPDX 3.0 is the current major spec listed by SPDX at the time of this document.

https://spdx.dev/use/specifications/

---

## Compatibility precedents

**Rust — stability without stagnation**

Rust deliberately separates unstable evolution from strong Stable promises and uses opt-in editions/explicit deprecation to evolve without casually breaking existing software.

https://rust-lang.github.io/rfcs/3085-edition-2021.html

https://rust-lang.github.io/rfcs/1105-api-evolution.html

https://rust-lang.github.io/rfcs/1270-deprecation.html

**Kubernetes deprecation**

Kubernetes explicitly versions APIs and does not remove API elements from the same version, providing a useful precedent for Evrosion contract-major evolution.

https://kubernetes.io/docs/reference/deprecation-policy/

**Android API levels**

Android's minimum/target API concepts demonstrate separating application compatibility targeting from the overall OS release.

https://developer.android.com/guide/topics/manifest/uses-sdk-element

**Linux userspace ABI documentation**

Linux explicitly categorizes interface stability rather than treating every visible interface identically.

https://www.kernel.org/doc/html/latest/admin-guide/abi.html

---

## Documentation precedents

**Architectural Decision Records**

ADRs preserve a significant decision and its rationale.

https://adr.github.io/

**Diátaxis**

Diátaxis distinguishes tutorials, how-to guides, reference and explanation based on user need.

https://diataxis.fr/start-here/

**Write the Docs**

Write the Docs recommends documentation sources live near the code they describe and avoiding duplicated canonical content.

https://www.writethedocs.org/guide/writing/docs-principles/

---

## EU Cyber Resilience Act — future commercial relevance

As of 2026-09-21:

- manufacturer reporting obligations under Article 14 apply from **2026-09-11**;
- main CRA obligations apply from **2027-12-11**;
- special rules exist for free/open-source software and open-source software stewards;
- commercial products with digital elements face vulnerability-handling/support obligations.

This does not turn early non-commercial public development into a reason to stop.

It means commercial Evrosion/OEM releases must receive jurisdiction-specific legal/compliance review before market placement.

Official European Commission / EUR-Lex:

https://digital-strategy.ec.europa.eu/en/policies/cra-reporting

https://digital-strategy.ec.europa.eu/en/policies/cra-open-source

https://digital-strategy.ec.europa.eu/en/policies/cra-summary

https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847

---

# 6. CONSOLIDATED LOCKED OUTCOME

With R-007 through R-011, Evrosion now has a coherent path from the approaching first boot to a credible public 0.1:

```text
FIRST REAL BOOT
      ↓
M0 ENGINEERING PROOF
      ↓
REPO / LICENSE / SECURITY HYGIENE
      ↓
PUBLIC GITHUB PROJECT
      ↓
M1 KERNEL SPINE
      ↓
M2 CAPABILITY USERSPACE
      ↓
M3 PERSISTENT GENERATIONS + ROLLBACK
      ↓
M4 GRAPHICAL SYSTEM + NATIVE APP
      ↓
M5 MINIMAL .ZION PLATFORM
      ↓
FULL END-TO-END ACCEPTANCE PROOF
      ↓
EVROSION 0.1 — DEVELOPER PREVIEW
      ↓
FIRST SERIOUS COMMUNITY RECRUITMENT
      ↓
M6 CONNECTED / REAL-HARDWARE EXPANSION
```

The most important strategic discipline is:

> **Do not let public-project infrastructure, compatibility promises, marketplace dreams, websites, AI, real hardware, or community excitement distort the 0.1 architecture proof.**

At the same time:

> **Do not wait until 1.0 to build the legal, repository, documentation and contribution foundations that allow other talented people to join.**

---

# 7. FINAL SUPERFILE PRINCIPLE

> **Evrosion should become public as a small but real operating system, evolve through explicit compatibility contracts rather than accidental promises, allow software to exist independently of an official store, preserve its architectural memory in executable and versioned form, and refuse to call 0.1 finished until the actual capability/recovery architecture survives the exact failures it claims to survive.**

---

# R-007 THROUGH R-011 COMPLETE — CONSOLIDATED BULK DIRECTION
