Public technical edition. Editorial changes remove development-workspace instructions; technical requirements and clause identities remain. The source map records actual edition hashes.

# Evrosion R-006 — Licensing, Contributor Rights, Commercial Exceptions & Trademark Policy

**Status:** ACCEPTED DESIGN DIRECTION — LEGAL IMPLEMENTATION REQUIRES COUNSEL REVIEW  
**Series:** R — Release, Project & Sustainability  
**Decision:** R-006  
**Purpose:** Define the licensing architecture for Evrosion, preserve a genuinely open core, keep the future commercial-licensing model legally possible, make third-party application/driver development practical, define contributor rights without copyright assignment, and protect the Evrosion identity from confusing forks or certification abuse.

> **Core rule:** The Evrosion core stays genuinely open. Organizations that want to distribute proprietary modifications to commercially relicensable Evrosion core may buy alternative rights. Applications and drivers must not be accidentally forced into the core's copyleft merely for using documented Evrosion interfaces.

---

# 1. Why R-006 Exists

Evrosion has already made several decisions that only work if the legal structure is designed correctly:

- the core OS is open source;
- owner control must remain real;
- security updates remain free;
- there are no ads, mandatory telemetry, forced accounts, or artificial crippling in the core;
- commercial licensing may later allow organizations to keep appropriate modifications proprietary;
- ordinary open-source users never need to pay simply to use, study, modify, or redistribute Evrosion under the open-source license;
- contributors should preferably retain their copyrights;
- funding must not buy control over Evrosion's constitutional principles;
- the future Foundation should become the long-term steward of project identity and constitutional continuity.

A casual choice such as "just use MIT everywhere" would conflict with this model.

R-006 therefore separates:

```text
CORE SOFTWARE LICENSE
PUBLIC SDK / INTERFACE LICENSE
DOCUMENTATION LICENSE
CONTRIBUTOR INBOUND RIGHTS
COMMERCIAL ALTERNATIVE RIGHTS
TRADEMARK / CERTIFICATION RIGHTS
THIRD-PARTY LICENSES
```

These are different legal layers and should remain different.

---

# 2. Legal Design, Not a Substitute for Legal Counsel

This document defines the intended legal behavior.

It is **not** itself:

- a Contributor License Agreement;
- a commercial software license;
- a trademark registration;
- legal advice;
- a replacement for counsel in a chosen jurisdiction.

Before Evrosion accepts substantial external contributions or signs commercial licensing agreements, a qualified open-source/IP lawyer should translate this design into final legal instruments.

The technical repository may implement standard, unmodified licenses such as GPL-3.0 and Apache-2.0, but project-specific agreements must receive legal review.

---

# 3. Recommended Licensing Architecture

Evrosion should use a **multi-license architecture with clear boundaries**.

## A. Evrosion Core

Recommended default:

```text
GNU General Public License v3.0 only
SPDX-License-Identifier: GPL-3.0-only
```

with an alternative commercial license available from the authorized Evrosion rights steward for components for which Evrosion controls sufficient rights.

## B. Public Application / Driver / ABI Boundary

Recommended default:

```text
Apache License 2.0
SPDX-License-Identifier: Apache-2.0
```

for public interface material that third-party software needs to consume.

## C. Documentation

Recommended default:

```text
Creative Commons Attribution 4.0 International
SPDX-License-Identifier: CC-BY-4.0
```

for prose documentation unless a specific document states otherwise.

## D. Official Name / Logos / Certification Marks

Not granted by the source-code licenses.

Use is governed separately by:

```text
Evrosion Trademark Policy
Evrosion Certification Policy
```

## E. Third-Party Components

Remain under their original compatible licenses and must be tracked explicitly.

---

# 4. Why GPLv3 for the Core

GPLv3 is a strong-copyleft open-source license.

That means a recipient may:

- use the covered software;
- study it;
- modify it;
- redistribute it;
- sell copies;

but distribution of covered modified work carries source-code/copyleft obligations.

This gives Evrosion the exact economic fork it wants:

```text
OPTION 1:
Use Evrosion under GPLv3
→ keep covered distributed modifications open

OPTION 2:
Buy commercial alternative rights
→ distribute agreed covered modifications under proprietary terms
```

A permissive license would largely remove the reason to buy the commercial exception.

---

# 5. Why Not MIT / BSD for the Core

MIT/BSD-style licensing is excellent when the goal is maximum downstream freedom to close modifications.

Projects such as FreeBSD, Fuchsia, Haiku and Redox intentionally use permissive licensing to allow proprietary derivatives.

That is legitimate.

It is simply not Evrosion's chosen economic model.

If the Evrosion core were MIT/BSD:

```text
OEM takes core
→ modifies it
→ distributes proprietary binary
→ does not publish modifications
→ does not need commercial exception
```

That defeats a central R-001 revenue option.

Therefore permissive licensing should be used deliberately at ecosystem boundaries, not indiscriminately across the core.

---

# 6. Why Not Apache-2.0 for the Entire Core

Apache-2.0 is a strong permissive license with an explicit patent grant.

It is excellent for SDK/interface material.

But, like MIT/BSD, it generally permits proprietary derivatives.

That would remove the copyleft/commercial-exception leverage from the core.

Apache-2.0 therefore belongs primarily at Evrosion's public compatibility boundary.

---

# 7. Why Not MPL-2.0 for the Entire Core

MPL-2.0 uses **file-level copyleft**.

Modified MPL-covered files generally remain MPL-covered, but MPL is deliberately designed to permit those files to be combined with larger proprietary works.

That flexibility is useful for many projects.

For Evrosion, however, it creates too many ways to build proprietary larger works around the core without purchasing alternative rights.

MPL may be useful for some future independent components, but it should not be the default Evrosion core license.

---

# 8. Why Not AGPL for the Base OS

AGPL extends copyleft obligations to certain network-server use cases.

That solves a different problem:

```text
modified server software
running as a network service
without distribution
```

Evrosion's primary problem is distributed operating-system software and devices.

Using AGPL for the base OS would introduce additional complexity with little benefit.

Future Evrosion-operated cloud services may choose licenses independently.

---

# 9. Why GPLv3 Rather Than GPLv2

GPLv3 is a better philosophical and operational fit for Evrosion.

Relevant properties include:

- explicit modern patent provisions;
- internationally clarified "convey" terminology;
- provisions concerning installation information for covered software in user products;
- improved handling of certain anti-circumvention/device-lockdown behavior;
- compatibility with Apache-2.0 in the GPLv3 direction.

The installation-information requirement is particularly aligned with:

```text
F-002 Absolute Ownership
Layer 3
owner ability to install modified system software
```

Evrosion should not design a consumer device that uses copyleft software while technically preventing the owner from replacing the covered code.

---

# 10. GPL-3.0-only vs GPL-3.0-or-later

Recommended Evrosion default:

```text
GPL-3.0-only
```

Reason:

Evrosion should explicitly know which legal terms govern the core.

Using:

```text
GPL-3.0-or-later
```

would allow downstream recipients to choose future GPL versions published by the FSF even if Evrosion has not reviewed them.

Evrosion's architecture already favors:

> stable explicit contracts, deliberate migration, no automatic unknown future semantics.

The same principle fits licensing.

If a future GPL version is beneficial, Evrosion can deliberately evaluate migration.

The contributor-rights agreement described later should be designed so that a future project-wide relicensing does not require individually locating thousands of historical contributors.

---

# 11. Open-Core Permanence Guarantee

The commercial model must not become a path to secretly close canonical Evrosion.

Lock the following principle:

> **Every canonical Evrosion Core release remains available under an OSI-approved open-source license.**

The intended default is GPL-3.0-only.

Commercial licensing is:

```text
ADDITIONAL PERMISSION
```

not:

```text
A FUTURE REPLACEMENT FOR OPEN SOURCE
```

The company may sell proprietary exceptions.

It may not transform the canonical core into a proprietary-only product while continuing to call that the community's Evrosion core.

---

# 12. Commercial Exceptions vs "Paying to Use Evrosion"

Ordinary people and companies may use Evrosion commercially under GPLv3.

The open-source license must not prohibit business use.

The Open Source Definition prohibits discrimination against fields of endeavor.

Therefore the commercial license is **not**:

> "businesses must pay to use Evrosion."

It is:

> "if your distribution/modification model is incompatible with the open-source copyleft obligations, Evrosion may offer alternative commercial rights."

This distinction must remain explicit in all future marketing.

---

# 13. Commercial Alternative License

For components where Evrosion controls sufficient copyright and patent rights, Evrosion Systems may later sell a commercial alternative license.

Potential rights may include permission to:

- modify covered Evrosion Core code;
- keep agreed modifications proprietary;
- redistribute covered binaries;
- integrate the covered code into proprietary products;
- receive commercial support;
- receive certification/integration assistance.

Exact terms, pricing, per-device rules, developer-seat rules, duration and support are later commercial decisions.

---

# 14. Commercial License Does Not Automatically Grant Official Status

Three concepts remain separate:

```text
SOURCE RIGHTS
OFFICIAL EVROSION IDENTITY
EVROSION CERTIFICATION
```

Buying proprietary-source rights does **not** automatically permit:

- calling a modified product "Official Evrosion";
- using the official Evrosion logo as product branding;
- claiming "Evrosion Certified";
- claiming Foundation endorsement;
- signing builds with the Official Evrosion release authority.

Those require separate trademark/certification authorization.

---

# 15. Money Cannot Buy Constitutional Authority

R-001 and R-002 remain authoritative.

An OEM cannot pay Evrosion to make an **official/certified Evrosion product** that violates core product laws such as:

- mandatory hidden telemetry;
- removal of owner sovereignty;
- fake Layer 3;
- undisclosed control channels;
- misleading official trust state.

A third party may exercise lawful open-source modification rights and create a fork.

But if its product violates official Evrosion requirements, it must not be represented as Official Evrosion or Evrosion Certified.

This is enforced primarily through:

```text
trust signatures
trademarks
certification
contracts
```

not by corrupting the open-source license with field-of-use restrictions.

---

# 16. Fork Freedom Is Real

GPL-covered Evrosion may be forked.

A fork may make changes Evrosion itself strongly disagrees with.

Open source means the project cannot say:

> "You may modify it, except in ways we dislike."

The code license permits lawful modification.

Evrosion protects users from confusion by protecting the **identity**, not by pretending forks do not have software freedoms.

---

# 17. The Public SDK / Interface Boundary

Third-party applications must be able to target Evrosion without accidentally becoming GPL-covered merely because they use ordinary platform interfaces.

Therefore app-facing material should normally be Apache-2.0.

Examples:

- public syscall definitions;
- public capability/API IDL;
- generated application bindings;
- ABI structures;
- public headers;
- SDK runtime glue intended to be incorporated into third-party programs;
- application templates;
- minimal example applications;
- driver-facing public API definitions;
- package-format parsing interfaces intended for developers.

This creates a legally clean platform boundary.

---

# 18. seL4 Is a Useful Precedent

seL4 uses:

- GPL for its kernel;
- permissive licensing for user code and syscall headers;
- an explicit boundary making clear that ordinary user programs calling kernel services may use any license.

Evrosion should use the same architectural idea, adapted for:

```text
capabilities
typed IPC
IDL-generated bindings
.zion applications
userspace drivers
```

The GPL protects the core implementation.

The public interface lets ecosystems form above it.

---

# 19. Consider a Narrow System-Interface Exception

Depending on final counsel review, Evrosion may add a narrow GPLv3 exception or explicit license notice clarifying that ordinary third-party programs using documented Evrosion system interfaces do not become GPL-covered merely by:

- issuing syscalls;
- using capability IPC;
- using generated public IDL bindings;
- consuming documented platform APIs.

This should be drafted carefully.

Do **not** invent a homemade legal exception in code without review.

The safer baseline is to license the relevant public interface files themselves under Apache-2.0.

---

# 20. Proprietary Applications Are Allowed

Evrosion is an open operating system.

It is not required that every program running on it be open source.

A proprietary application should be able to:

```text
use Evrosion APIs
receive capabilities
use IPC
ship as .zion
run sandboxed
```

without inheriting the core's GPL license merely from normal platform use.

Application marketplace policy is a separate R-series question.

---

# 21. Proprietary Drivers Must Remain Possible

Evrosion should strongly prefer open drivers where practical.

But an OS intended to run across real hardware should not accidentally make third-party proprietary userspace drivers legally impossible.

Therefore the public driver SDK/interface boundary should also use permissive terms where appropriate.

Authority remains controlled technically through capabilities.

A proprietary driver does not receive ambient privilege merely because it exists.

---

# 22. Core vs Extension Is a Legal Boundary Too

A component is not exempt from copyleft merely because a developer calls it a "plugin."

Legal classification depends on actual integration and applicable law.

Therefore Evrosion should deliberately design clean process/IPC/component boundaries.

This has architectural benefits **and** licensing benefits.

Do not rely on filename tricks to manufacture legal separation.

---

# 23. Recommended Core Scope

Unless specifically classified otherwise, the following Evrosion-authored implementations should begin GPL-3.0-only:

- kernel implementation;
- Root Supervisor;
- core bootstrap/runtime services;
- core capability infrastructure;
- core system lifecycle;
- update engine;
- recovery implementation;
- official system-generation machinery;
- core storage/filesystem services;
- core networking implementation;
- core security services;
- package verification/install mechanisms;
- system trust-state components;
- official core shell/system UI implementation where part of the OS;
- core diagnostics/observability implementation;
- other code that constitutes the Evrosion platform itself.

Exact repository classification may evolve.

The **interface** to those components may use Apache-2.0.

---

# 24. Recommended Permissive Scope

Apache-2.0 is the preferred default for Evrosion-authored:

- public SDK;
- syscall/ABI declarations intended for external consumption;
- app IDLs;
- driver IDLs;
- generated client bindings;
- app-side runtime glue;
- public development libraries where proprietary linking is intentionally permitted;
- templates/examples;
- interoperability libraries whose adoption matters more than copyleft;
- tools/libraries intended to be embedded into third-party build systems.

A file's license should follow its intended ecosystem role, not convenience.

---

# 25. Development Tools

Tools such as:

```text
ev
build tooling
debugging tooling
image tooling
test harnesses
```

may generally be GPL-3.0-only if they are part of Evrosion itself.

Merely using a GPL tool to build separate software does not automatically make the tool's output GPL-covered.

However, if a tool copies runtime material into produced applications, that runtime material must have an appropriate permissive/runtime license.

Therefore generated SDK/runtime fragments should be explicitly classified.

---

# 26. Documentation License

Recommended:

```text
CC-BY-4.0
```

for general Evrosion documentation.

Reasons:

- documentation can be copied;
- translated;
- adapted;
- redistributed commercially;
- attribution remains required;
- Creative Commons explicitly supports CC licensing for documentation even though it recommends software-specific licenses for software itself.

Architecture documents, tutorials and developer guides should be reusable.

---

# 27. Code in Documentation

Code samples inside documentation can create confusion if the prose is CC-BY but the sample is intended for software use.

Policy:

- substantial reusable code examples should state a software license;
- default to Apache-2.0 for app/SDK examples;
- trivial snippets need not be over-lawyered where copyright does not meaningfully attach;
- generated templates should carry explicit SPDX identifiers.

---

# 28. Brand Assets Are Separate

Official logos, wordmarks, badges and certification graphics are not automatically granted for unrestricted product branding merely because the files are visible in the repository.

The code license does not grant trademark rights.

Brand files should contain a notice pointing to:

```text
TRADEMARKS.md
```

The artwork's copyright license and trademark permission are separate questions.

---

# 29. Contributor Copyright Ownership

Evrosion should **not** require routine contributors to assign copyright ownership to the company or founder.

Default principle:

> **Contributors retain copyright in their original contributions.**

This reduces distrust and respects contributor ownership.

The project instead receives a broad non-exclusive license through an Evrosion Contributor Agreement.

This resembles established models used by projects such as Apache/Qt/Google, where contributors may retain ownership while granting substantial project rights.

---

# 30. Why a DCO Alone Is Not Enough

The Developer Certificate of Origin is useful for provenance.

It certifies that the contributor has the right to submit the contribution under the indicated open-source license.

But the Linux Foundation explicitly notes:

> the DCO is not itself a license and does not grant additional license rights.

Therefore a pure:

```text
DCO + GPL contribution
```

would not necessarily give Evrosion the broad rights required to commercially relicense that contributor's copyright.

Evrosion's business model therefore needs more than a DCO alone.

---

# 31. Evrosion Contributor Agreement (ECA)

Evrosion should create its own project-branded Contributor License Agreement:

```text
Evrosion Contributor Agreement (ECA)
```

with:

- Individual ECA;
- Entity/Corporate ECA.

The name is project-specific.

The legal text should be based on a recognized contributor-agreement model and reviewed by counsel rather than invented casually.

Harmony CLA templates are one useful legal starting point because they were created specifically as reusable FOSS contributor-agreement templates.

---

# 32. ECA — Required Semantics

The final ECA should aim to achieve all of the following.

## Contributor keeps ownership

No routine copyright assignment.

## Broad non-exclusive project rights

Contributor grants Evrosion sufficient rights to:

- use;
- reproduce;
- modify;
- distribute;
- publicly perform/display where relevant;
- sublicense;
- relicense;

the contribution.

## Open + commercial relicensing

The grant must be broad enough to permit Evrosion to distribute the contribution:

```text
under canonical open-source terms
AND
under separately negotiated commercial terms
```

## Patent grant

Where the contributor controls relevant patent claims necessarily infringed by the contribution, the ECA should include an appropriate patent license.

## Authority representation

Contributor confirms they possess the rights they claim to grant.

## Employer rights

If an employer owns the contribution, appropriate employer/entity authorization is required.

## No ownership seizure

Contributor remains free to use/license their original contribution elsewhere.

---

# 33. Open-Core Protection Inside the ECA

A broad commercial-relicensing CLA can scare contributors.

Evrosion should therefore legally encode a reciprocal project promise as far as practicable:

> **Contributions accepted into the canonical Evrosion Core remain available as part of the open-source Evrosion Core.**

Evrosion may also commercial-license them.

It should not take a community core contribution, delete it from the open project, and turn that same canonical core functionality into a proprietary-only Evrosion product.

Exact covenant wording requires counsel.

---

# 34. ECA Transfer / Foundation Transition

The ECA must survive Evrosion's future governance transition.

Avoid a future disaster where:

```text
10,000 contributors
→ Foundation created
→ every contributor must be found and re-sign
```

The agreement should permit transfer/assignment of the project-side rights to an authorized successor such as:

- Evrosion Foundation;
- an Evrosion project steward controlled under R-002;
- Evrosion Systems where commercially necessary;

while binding the successor to the agreement's open-core obligations.

Exact recipient structure should be finalized with corporate/IP counsel.

---

# 35. Company vs Foundation Rights

Long-term preferred structure:

```text
EVROSION FOUNDATION
  protects:
  - constitutional continuity
  - project identity
  - trademark stewardship
  - open-source permanence
  - contributor trust

EVROSION SYSTEMS
  operates:
  - commercial licensing
  - OEM agreements
  - enterprise support
  - paid services
  - marketplace/cloud business
```

The Foundation and company may cross-license necessary rights.

The legal design must preserve:

```text
company can do business
without
company being able to permanently close the community core
```

Exact ownership structure is deferred to professional legal design.

---

# 36. ECA + DCO Together

Recommended contribution process:

```text
ECA once per contributor/entity
+
DCO Signed-off-by on each commit
```

Why both?

## ECA

Provides the broader inbound rights required by Evrosion's dual/commercial licensing strategy.

## DCO

Provides per-commit provenance certification and a visible chain of responsibility.

This is more process than a DCO-only project, so the contribution UX should make signing painless.

---

# 37. Contributor-Friction Mitigation

CLAs can deter contributors, especially when signed with a for-profit project.

Evrosion should counter that honestly:

- short plain-English explanation;
- no copyright assignment;
- contributor retains rights;
- canonical core remains open;
- clearly explain why commercial relicensing is needed;
- no hidden rights grab;
- one-time electronic signature;
- immediate status feedback in PRs;
- separate individual/entity paths.

Do not bury the rationale in legalese.

---

# 38. Small Contributions

Counsel may decide that very small/non-copyrightable contributions can be accepted without full ECA formalities.

Examples may include:

- typo corrections;
- trivial factual corrections;
- tiny noncreative changes.

But automated contribution policy should remain simple.

Do not allow "small contribution" exceptions to become a loophole through which meaningful copyrighted code enters without appropriate rights.

---

# 39. Employer / University / Client Rights

A contributor may personally write code but not own the copyright.

Potential owners include:

- employer;
- university;
- client;
- contracting entity.

ECA/DCO process should explicitly remind contributors to check this.

Entity ECA should exist for corporate contributors.

High-value code with unclear provenance should not be merged until ownership is resolved.

---

# 40. Contribution provenance

A contributor may submit only material they have the right to license to the
project. Establish provenance and retain required notices. Reject material
copied from incompatible sources or whose rights cannot be established.

---

# 41. Third-Party Code Is the Biggest Relicensing Trap

The commercial-license model only works for code Evrosion has sufficient rights to commercially relicense.

Suppose Evrosion merges:

```text
large external GPL-only component
```

whose copyright belongs to unrelated authors.

Evrosion may be permitted to redistribute it under GPL.

But Evrosion cannot simply sell proprietary rights to someone else's copyright.

Therefore the project must track **relicensability**, not merely "GPL compatibility."

---

# 42. Commercially Relicensable Core

Maintain an explicit concept:

```text
COMMERCIAL-RELICENSE-ELIGIBLE CORE
```

A component belongs in this set only when its rights chain permits the commercial alternative.

Typical eligible sources:

1. original code written by the founder/project entity;
2. ECA-covered contributions;
3. third-party permissive code whose license permits the planned proprietary redistribution while preserving required notices.

Potentially non-eligible:

- third-party GPL-only code;
- LGPL/MPL code with obligations inconsistent with the intended commercial package;
- source-available code;
- code with unknown provenance;
- incompatible custom-license code.

---

# 43. Third-Party Copyleft Isolation

Evrosion may still use third-party copyleft software where beneficial.

But such code should be:

- legally reviewed;
- isolated;
- clearly identified;
- excluded from commercial relicensing claims unless appropriate rights exist;
- replaceable where practical.

Examples might include standalone tools/utilities distributed alongside Evrosion.

Do not quietly mix them into the commercially relicensable core and discover the problem years later.

---

# 44. Linux Code Warning

The Linux kernel is GPL-2.0-only.

Evrosion's recommended core is GPL-3.0-only.

GPLv2-only and GPLv3 code are not generally license-compatible as one combined derivative work.

Therefore:

> **Do not copy Linux kernel GPLv2-only implementation code into Evrosion.**

Beyond compatibility, Linux copyright is distributed across many contributors, which would also undermine Evrosion's commercial-exception rights chain.

Learning from algorithms, documented behavior, specifications and published ideas is different from copying copyrighted implementation.

When uncertain, clean-room/reimplementation practices and legal review should be used.

---

# 45. Rust / Apache Dependencies

Apache-2.0 is compatible in the direction needed for incorporation into GPLv3-covered work.

Therefore many common Rust crates licensed under:

```text
MIT OR Apache-2.0
```

are structurally easier to use in Evrosion's GPLv3 core, subject to normal license compliance and technical/security review.

The original permissive notices/licenses still need to be preserved.

---

# 46. Dependency License Policy

Default preference for core dependencies:

```text
MIT
Apache-2.0
BSD-2-Clause
BSD-3-Clause
ISC
Zlib
other clearly compatible permissive licenses
```

Case-by-case review:

```text
LGPL
MPL
GPL
EPL
CDDL
other copyleft
```

Normally reject from commercially relicensable core without explicit legal review:

```text
GPL-2.0-only
AGPL
SSPL / source-available restrictions
BUSL-style source-available terms
custom non-standard licenses
no-license / unknown license
```

This is a policy default, not a declaration that every listed license is universally incompatible in every architecture.

---

# 47. No-License Code Means No Permission

Publicly visible source code is not automatically open source.

If code has no clear license, Evrosion must not assume it may be copied.

A GitHub repository being public is not itself permission to incorporate the code.

Unknown-license code should be treated as unavailable until rights are clarified.

---

# 48. SPDX Everywhere Practical

Use SPDX license identifiers consistently.

Examples:

```text
SPDX-License-Identifier: GPL-3.0-only
SPDX-License-Identifier: Apache-2.0
SPDX-License-Identifier: CC-BY-4.0
SPDX-License-Identifier: MIT OR Apache-2.0
```

Linux Foundation and SPDX guidance strongly support per-file identifiers because they make automated compliance far easier.

---

# 49. Repository License Layout

Recommended top-level structure:

```text
LICENSE
LICENSES/
    GPL-3.0-only.txt
    Apache-2.0.txt
    CC-BY-4.0.txt
    <third-party license texts>

LEGAL.md
LICENSE_POLICY.md
TRADEMARKS.md
CONTRIBUTING.md
THIRD_PARTY_NOTICES.md
```

Possible later additions:

```text
CLA/
    README.md
    ECA-individual.pdf
    ECA-entity.pdf

legal/
    component-license-map.toml
    commercial-relicense-map.toml
```

---

# 50. Top-Level LICENSE Behavior

Because Evrosion intentionally uses multiple licenses, the top-level `LICENSE` file should not falsely imply one license applies to every file.

It should explain the classification.

Example structure:

```text
Evrosion is a multi-license project.

Evrosion Core:
GPL-3.0-only unless otherwise stated.

Public SDK/interface code:
Apache-2.0 where marked.

Documentation:
CC-BY-4.0 where marked.

Third-party code:
its stated license.

Trademarks:
not granted by these licenses; see TRADEMARKS.md.
```

Per-file SPDX identifiers resolve the exact case.

---

# 51. Component License Map

Maintain a machine-readable/legal-reviewable component map.

For each component:

- path;
- purpose;
- outbound license;
- copyright ownership category;
- ECA coverage status;
- third-party dependencies;
- commercially relicensable: yes/no/partial;
- trademark relevance;
- required notices.

This will matter enormously once OEM commercial licensing begins.

---

# 52. Automated License Compliance

CI should eventually reject:

- source files missing required SPDX tags;
- dependencies under prohibited/unknown licenses;
- incompatible license combinations;
- missing third-party notices;
- new copyleft dependency without explicit approval.

Possible tooling may include:

- cargo-deny;
- cargo-about;
- REUSE;
- SPDX/SBOM tooling;
- dependency scanners.

Exact tooling belongs to R-007.

---

# 53. SBOM / Provenance

Formal releases should eventually produce a Software Bill of Materials containing:

- component;
- version;
- source;
- license;
- hash;
- dependency relationships.

R-003 handles release trust.

R-006 adds:

> license provenance must be inspectable alongside software provenance.

---

# 54. Trademark Is Not Copyright

Open-source software licenses do not automatically grant a right to present modified software as the official product.

Mozilla and Apache both separate source-code freedoms from trademark identity.

Evrosion should do the same.

This is essential because:

```text
fork freedom
```

and:

```text
protection from user confusion
```

can coexist.

---

# 55. Core Evrosion Marks

Potential protected marks include:

```text
EVROSION
Evrosion logo
EVROSION CERTIFIED
Official Evrosion release badges
future marketplace marks
```

The final trademark list should be maintained publicly.

The `.zion` extension is primarily a technical format identifier and should not automatically be treated like an exclusive product brand.

---

# 56. Trademark Ownership Timeline

Founder era:

- founder/project entity controls Evrosion identity;
- registration pursued when resources justify it.

Long-term:

- Foundation should become the preferred steward/owner or legally controlling guardian of major Evrosion marks under R-002.

The transfer mechanism must be designed so that post-founder shareholders cannot sell the project identity independently of Foundation governance.

---

# 57. Trademark Clearance Before Major Public Branding

Before significant public launch/registration:

- search relevant trademark databases;
- search software/computer classes;
- search confusingly similar marks;
- review EU/global strategy;
- obtain professional clearance if budget permits.

A normal web search is not a substitute for trademark clearance.

Given early budget constraints, registration timing may be staged.

Clearance is more urgent than registering every jurisdiction immediately.

---

# 58. Official Evrosion

"Official Evrosion" is already defined cryptographically by R-003.

Trademark policy should reinforce that.

A build is not Official merely because:

- it looks identical;
- it uses the logo;
- it was built from official source;
- it claims compatibility.

Only release authority defined by R-003 can issue Official Evrosion releases.

---

# 59. Unmodified Redistribution

Trademark policy should allow reasonable redistribution of genuine official Evrosion artifacts when:

- artifacts are unmodified;
- official signatures remain intact;
- origin is accurately represented;
- no extra endorsement is implied;
- required notices remain intact.

Exact trademark wording is deferred to final policy.

---

# 60. Reproducible Independent Builds

An independent party may rebuild Evrosion source bit-for-bit.

Even if the result is identical:

- they may truthfully say it is an independent rebuild of Evrosion source;
- they may publish verification results;
- they may not claim project signing authority;
- they may not fabricate an Official Evrosion signature.

This preserves R-003's trust model.

---

# 61. Modified Fork Naming

A materially modified downstream distribution should generally use its own product name.

Permitted descriptive phrases should include things like:

```text
based on Evrosion
derived from Evrosion
compatible with Evrosion
built using Evrosion technology
```

when truthful and non-confusing.

Not permitted without authorization:

```text
Official Evrosion <something>
Evrosion Certified <something>
Evrosion Pro
Evrosion Enterprise
```

for unrelated third-party products in ways likely to imply project approval.

---

# 62. Forks May State Origin

Trademark protection must not become censorship.

A fork must be allowed to truthfully state that it is derived from Evrosion.

Reviews, comparisons, criticism, security research and documentation may use the Evrosion name descriptively where legally permitted.

The policy's target is **confusion**, not criticism.

---

# 63. Evrosion Certified

`Evrosion Certified` is a special trust mark.

It should be granted only through the certification process.

Certification may depend on:

- hardware validation;
- owner-sovereignty requirements;
- update/recovery behavior;
- diagnostic integrity;
- firmware expectations;
- required tests;
- branding rules.

Open-source code freedom does not grant certification status.

---

# 64. OEM Branding

An OEM may say:

```text
Ships with Official Evrosion
```

or use approved co-branding only when it is actually distributing authorized official/certified software under applicable trademark agreements.

A proprietary fork should use its own primary brand.

Commercial licensing and branding should be contractually separate.

---

# 65. Trademark Policy Should Be Public

Publish a plain-language `TRADEMARKS.md` before the project becomes large enough for confusion to matter.

It should explain:

- official marks;
- acceptable descriptive use;
- modified builds;
- unmodified redistribution;
- screenshots/articles/books;
- compatible products;
- domain/account naming;
- certification marks;
- how to request permission.

Do not force ordinary community references through a lawyer.

---

# 66. Avoid Trademark Bullying

Trademark exists to preserve source/quality identity.

It should not be used to attack:

- legitimate criticism;
- benchmarks;
- security research;
- news reporting;
- educational materials;
- honest compatibility statements;
- fair/nominative references.

Policy enforcement should target real confusion or abuse.

---

# 67. Commercial Forks Without Evrosion Branding

A third party may be legally entitled to create its own fork under the applicable open-source license.

If fully rebranded and compliant with the software license, Evrosion should not pretend trademark law lets it prohibit the software fork itself.

This is expected.

The competitive defense is:

- better engineering;
- trusted official releases;
- community;
- certification;
- trademark identity;
- update infrastructure;
- ecosystem;
- support.

---

# 68. Patent Strategy

GPLv3 and Apache-2.0 both contain patent-related provisions.

The ECA should contain an appropriate contributor patent grant.

Evrosion should avoid casually filing offensive software patents merely to create tollbooths around the open project.

If patents are ever acquired, a later patent policy should address:

- defensive use;
- retaliation against patent aggression;
- open-source users;
- commercial licensees;
- Foundation stewardship.

No immediate patent portfolio is required for M0/0.1.

---

# 69. Patent Contributions

A contributor or corporation should not be able to:

```text
contribute implementation
→ encourage adoption
→ later assert necessarily infringed patents against users of that contribution
```

The final ECA must address this risk with qualified legal drafting.

Apache-2.0 already includes an explicit contributor patent grant for Apache-covered interface material.

---

# 70. No Custom Open-Source License

Do **not** invent:

```text
Evrosion Public License v1
```

for the open-source core.

OSI/FSF/Linux Foundation guidance and decades of ecosystem experience favor standard well-understood licenses.

Custom licenses:

- increase legal-review cost;
- hurt dependency compatibility;
- confuse contributors;
- create adoption friction.

Use standard licenses plus separate commercial/trademark contracts.

---

# 71. No "Ethical Use" Restriction Inside the Open License

Evrosion may have values.

But an OSI-compliant open-source license cannot forbid particular people, industries or fields of endeavor merely because the project dislikes them.

Do not add clauses such as:

```text
no military use
no surveillance companies
no competitors
non-commercial only
```

to the GPL code.

Such restrictions would change the open-source nature of the license.

Project identity/certification relationships can be governed separately.

---

# 72. No Source-Available Pretending to Be Open Source

If a future Evrosion product uses a source-available but non-OSI license, it must be described accurately.

Do not call something "open source" merely because source is visible.

The canonical Evrosion Core remains genuinely open source.

---

# 73. Proprietary Evrosion Services

R-006 does not require every business-side system to be open source.

Examples that may use separate licensing later:

- hosted cloud infrastructure;
- paid enterprise management service;
- marketplace backend;
- commercial support tooling;
- internal operational systems.

But client-side/core components governed by the Open-Core Permanence Guarantee remain open according to their canonical license.

Exact boundaries are future R-series decisions.

---

# 74. Free Security Updates Remain Free

Commercial licensing does not alter R-001.

Essential security updates for supported Evrosion installations remain free.

A customer does not need a paid commercial license merely to obtain security patches for the open-source system.

Paid support/SLA services are separate.

---

# 75. Community Contributions Cannot Be Secretly Reclassified

Once a contribution has entered canonical open-source Evrosion Core under the ECA/open license:

- it remains available in open-source history;
- a commercial license may additionally use it;
- the project cannot erase the public licensing grant already provided to recipients.

Open-source recipients retain rights already granted subject to the license terms.

---

# 76. License Change Governance

A future change to the canonical core license is a major governance event.

During founder era:

- founder has final authority under R-002;
- legal and community impact must be explicitly reviewed.

Post-founder:

- Foundation governance and user/community protections should apply;
- changing from an OSI-approved open-source license to proprietary/source-available core should be constitutionally prohibited or require the highest possible constitutional threshold.

Target principle:

> **The canonical core does not stop being genuinely open source through an ordinary board vote.**

---

# 77. Third-Party Notices Are Public

Release source/binary distributions should include required notices for third-party dependencies.

Users and OEMs should be able to answer:

- what third-party code is included;
- what license applies;
- where source can be obtained where required.

Do not hide dependency licenses in build-system metadata.

---

# 78. Package / Application Licensing

The `.zion` format itself must be license-neutral.

A `.zion` package may contain software under:

- open-source license;
- freeware/proprietary license;
- commercial license;
- mixed permitted licenses.

The format does not confer a license.

Marketplace policy later determines what packages may be offered through official channels.

---

# 79. `.zion` Format Specification

The public `.zion` specification and interoperability material should be permissively licensed, preferably Apache-2.0 for software/spec code artifacts and CC-BY-4.0 for prose specification text where appropriate.

Goal:

> anyone can implement `.zion` tooling without asking permission.

Official signing/certification authority remains separate.

---

# 80. Compatibility Implementations

Third parties should be allowed to independently implement:

- Evrosion APIs;
- `.zion`;
- public IPC protocols;
- file formats;
- interoperability tools;

subject to applicable law and the relevant permissive interface/spec licenses.

This makes Evrosion an actual platform rather than a permission gate.

---

# 81. Adversarial Review

## Failure: MIT core lets OEMs close everything for free
**Resolution:** GPL-3.0-only core + commercial alternative rights.

## Failure: GPL core scares proprietary app developers
**Resolution:** Apache-2.0 public SDK/IDL/interface boundary; possible narrow interface exception after counsel review.

## Failure: closed driver impossible
**Resolution:** permissive driver-facing public APIs; capability sandbox remains technical security boundary.

## Failure: GPL future version changes terms automatically
**Resolution:** GPL-3.0-only, deliberate future migration.

## Failure: canonical Evrosion becomes proprietary later
**Resolution:** Open-Core Permanence Guarantee + Foundation governance target.

## Failure: company cannot commercial-license contributor code
**Resolution:** ECA grants broad non-exclusive open/commercial relicensing rights.

## Failure: contributors lose ownership
**Resolution:** no routine copyright assignment; contributor keeps copyright.

## Failure: DCO mistaken for commercial relicensing permission
**Resolution:** ECA handles rights; DCO handles provenance.

## Failure: CLA scares contributors
**Resolution:** narrow transparent rationale, retained ownership, open-core covenant, one-time electronic workflow.

## Failure: employee contributes code they do not own
**Resolution:** entity ECA/employer authorization.

## Failure: AI contribution contains copied code
**Resolution:** contributor remains legally responsible for provenance; suspicious code rejected.

## Failure: third-party GPL code makes commercial exception impossible
**Resolution:** explicit commercially relicensable-core classification and dependency review.

## Failure: Linux GPLv2-only implementation copied into Evrosion
**Resolution:** prohibit direct incorporation into GPLv3-only core absent legal compatibility/right analysis; prefer clean implementation.

## Failure: dependency license discovered years later
**Resolution:** SPDX + license map + CI + third-party notices + SBOM.

## Failure: fork claims to be official Evrosion
**Resolution:** trademark policy + R-003 cryptographic official identity.

## Failure: project uses trademark to silence criticism
**Resolution:** explicit protection for truthful descriptive/nominative uses and criticism.

## Failure: paying OEM claims certification automatically
**Resolution:** commercial software rights separate from trademark/certification.

## Failure: project adds "ethical" restrictions and ceases being open source
**Resolution:** no field-of-use restrictions in open-source license.

## Failure: Foundation transition requires every contributor to re-sign
**Resolution:** ECA designed for authorized steward succession.

## Failure: company sale transfers Evrosion crown jewels without protection
**Resolution:** R-002 Foundation control + restricted successor semantics for contribution/trademark rights.

## Failure: custom Evrosion license kills adoption
**Resolution:** standard OSI-approved licenses only for open-source code.

---

# 82. Research Basis / Precedents

## Open Source Initiative — Open Source Definition

OSI requires open-source licenses to allow modification/derived works and prohibits discrimination against persons/groups or fields of endeavor.

https://opensource.org/osd

## Open Source Initiative — Approved Licenses

GPLv3, Apache-2.0, MPL-2.0 and other licenses used in this analysis are OSI-approved licenses.

https://opensource.org/licenses

## GNU GPL Version 3

GPLv3 provides strong copyleft and includes provisions concerning source, patents, installation information for User Products and future license versions.

https://www.gnu.org/licenses/gpl-3.0.html

## SPDX — GPL-3.0-only

SPDX distinguishes `GPL-3.0-only` from `GPL-3.0-or-later`.

https://spdx.org/licenses/GPL-3.0-only.html

## Apache License 2.0

Apache-2.0 grants broad copyright rights and an explicit contributor patent license.

https://www.apache.org/licenses/LICENSE-2.0

## Apache / GPLv3 Compatibility

Apache documents that Apache-2.0 code can be included in GPLv3 works in the relevant direction.

https://www.apache.org/licenses/GPL-compatibility

## Mozilla MPL 2.0 FAQ

Mozilla describes MPL-2.0 as file-level copyleft that allows combination with proprietary larger works.

https://www.mozilla.org/MPL/2.0/FAQ/

## seL4 Licensing Model

seL4 uses GPL for the kernel while licensing user code/syscall headers permissively so applications and drivers may use arbitrary licenses.

https://www.sel4.systems/Legal/license.html

## Qt Dual/Commercial Licensing

Qt demonstrates a mature model where open-source and commercial licensing coexist and external contributors retain copyright while granting rights allowing open/commercial relicensing.

https://www.qt.io/development/qt-framework/qt-licensing

https://www.qt.io/community/legal-contribution-agreement-qt

## Linux Foundation — DCO vs CLA

Linux Foundation guidance distinguishes DCO provenance certification from CLAs and explicitly notes that the DCO is not itself a license grant.

https://bestpractices.linuxfoundation.org/ip/contribution-mechanisms.html

https://bestpractices.linuxfoundation.org/ip/contribution-mechanisms-dco.html

## Developer Certificate of Origin 1.1

https://developercertificate.org/

## Harmony Contributor Agreements

Harmony provides reusable individual/entity contributor-license agreement templates and design guidance.

https://www.harmonyagreements.org/

https://www.harmonyagreements.org/agreements

## Apache Contributor Agreements

Apache uses contributor agreements while contributors retain rights in their contributions.

https://www.apache.org/licenses/contributor-agreements.html

## LLVM Relicensing Experience

LLVM documents how distributed historical copyrights made relicensing a large, multi-year effort, illustrating why Evrosion should settle contributor rights early.

https://llvm.org/docs/DeveloperPolicy.html

## SPDX / Linux Foundation License Marking

SPDX provides standard file-level identifiers and Linux Foundation guidance recommends their use.

https://spdx.dev/learn/handling-license-info/

https://www.linuxfoundation.org/licensebestpractices

## Creative Commons

Creative Commons recommends software-specific licenses for software but states CC licenses are suitable for software documentation and separate artistic material.

https://creativecommons.org/faq/

## Mozilla Trademark / Distribution Policy

Mozilla separates open-source software rights from trademark rights and requires separate compliance for branded distribution.

https://www.mozilla.org/foundation/trademarks/distribution-policy/

## Apache Trademark Policy

Apache permits truthful descriptive use while generally requiring modified distributions to use different product branding.

https://www.apache.org/foundation/marks/

https://www.apache.org/foundation/marks/faq/

## FreeBSD / Fuchsia / Haiku / Redox

These projects demonstrate the alternative permissive-OS licensing philosophy. Their approach maximizes downstream proprietary reuse, which is intentionally different from Evrosion's selected commercial-exception model.

https://www.freebsd.org/copyright/freebsd-license/

https://fuchsia.dev/fuchsia-src/contribute/governance/policy/open-source-licensing-policies

https://www.haiku-inc.org/documents/licenses/

https://github.com/redox-os/redox

---

# 83. Locked R-006 Laws

1. **Evrosion Core uses strong copyleft by default.**
2. **Recommended canonical core license is GPL-3.0-only.**
3. **The canonical Evrosion Core remains genuinely open source permanently.**
4. **Commercial licensing is an additional alternative, not a replacement for the open-source core.**
5. **Commercial use of GPL Evrosion does not itself require payment.**
6. **Organizations may buy alternative rights when they want to distribute covered core modifications under proprietary terms.**
7. **Public application/driver/ABI interfaces should normally use Apache-2.0.**
8. **Normal third-party applications must not become GPL merely for using documented Evrosion platform interfaces.**
9. **Proprietary applications and proprietary userspace drivers are allowed in principle.**
10. **Documentation should normally use CC-BY-4.0.**
11. **Official logos/trademarks are governed separately from code/document licenses.**
12. **Contributors retain copyright in their original contributions.**
13. **Evrosion uses a broad non-exclusive Contributor License Agreement rather than routine copyright assignment.**
14. **The Contributor Agreement must permit both canonical open-source distribution and commercial relicensing.**
15. **The Contributor Agreement must contain appropriate contributor patent rights/authority protections.**
16. **Entity/corporate contribution authorization must exist for employer-owned contributions.**
17. **DCO sign-off should supplement the Contributor Agreement for per-commit provenance.**
18. **A DCO alone is insufficient for Evrosion's intended commercial-relicensing model.**
19. **The Contributor Agreement must be designed to survive transition to the future Foundation/project steward without mass re-signing.**
20. **Canonical core contributions remain available in the open-source Evrosion Core even when also commercially licensed.**
21. **Evrosion must track whether each component is commercially relicense-eligible.**
22. **Third-party copyleft code must not silently contaminate the commercially relicensable core.**
23. **GPL-2.0-only Linux kernel code must not be casually copied into the GPL-3.0-only Evrosion core.**
24. **Permissive third-party dependencies are preferred where technically appropriate.**
25. **Unknown/no-license code must not be imported.**
26. **Every practical source/document file uses an SPDX identifier.**
27. **Third-party notices and license texts remain available in releases.**
28. **License compatibility/relicensability becomes a CI-enforced property as tooling matures.**
29. **Official Evrosion identity is protected by trademark and R-003 cryptographic trust, not by removing fork freedoms.**
30. **Modified forks generally use distinct primary branding but may truthfully state Evrosion origin/compatibility.**
31. **`Evrosion Certified` is reserved for explicit certification.**
32. **Commercial licensing does not automatically grant Official/Certified branding.**
33. **Evrosion trademarks must not be used to suppress legitimate criticism, research, reporting or truthful compatibility references.**
34. **No custom Evrosion open-source license should be invented.**
35. **No field-of-use/"ethical use"/non-commercial restriction may be added to the canonical open-source core license.**
36. **`.zion` remains license-neutral; proprietary and open packages can use the format.**
37. **The `.zion` public specification/interface should be openly implementable.**
38. **Essential security updates remain free under R-001.**
39. **Changing the canonical core away from genuine open source must be constitutionally blocked from ordinary future governance.**
40. **Final ECA, commercial-license, Foundation-rights and trademark documents require qualified legal review before they are relied upon as contracts.**

---

# 84. Repository preparation

**Public snapshot application record — 2026-11-12:** The founder formally
approved GPL-3.0-only for first-party Core software; Apache-2.0 for software and
interfaces in `idl/`, `tools/idl/`, `libs/userspace-contract/`,
`libs/userspace-runtime/`, `libs/app-identity/`, `libs/userspace-graphics/` and
`libs/graphics/`; and CC-BY-4.0 for eligible first-party prose. Third-party terms
remain unchanged. The [license policy](../../../LICENSE_POLICY.md), standard
texts and file-level annotations record the actual boundary. This application
does not create the deferred contributor, commercial, trademark or other legal
instruments below. The remaining section retains the original policy conditions.


Maintainers may prepare the following **technical/legal-structure decisions now**:

## May implement now

```text
LICENSE_POLICY.md
LEGAL.md
LICENSES/ directory
SPDX file headers
component license metadata
third-party license tracking
dependency license checks
clear Core vs SDK directory/license boundaries
TRADEMARKS.md placeholder describing policy direction
CONTRIBUTING.md note that substantive external contributions are not mergeable until ECA process is active
```

## Core source written by Evrosion

Mark new core files:

```text
SPDX-License-Identifier: GPL-3.0-only
```

once the founder formally applies GPL-3.0-only to those files/repository.

## Public SDK/interface code

Mark deliberately permissive interface files:

```text
SPDX-License-Identifier: Apache-2.0
```

only when they truly belong to the public compatibility boundary.

## Documentation

Mark eligible prose:

```text
SPDX-License-Identifier: CC-BY-4.0
```

where appropriate.

---

# 85. Legal instruments requiring review

Do not invent legally binding wording for:

- Evrosion Contributor Agreement;
- commercial proprietary license;
- trademark registration;
- OEM license;
- certification contract;
- Foundation/company IP transfer agreement.

Maintainers may draft **requirements/checklists** for counsel.

It should not silently create a homemade license and call it final.

---

# 86. Pre-Public-Repo Legal Gate

Before accepting substantial external code:

```text
1. GPL-3.0-only core decision formally applied
2. Apache-2.0 interface scope identified
3. documentation license identified
4. all existing code provenance reviewed
5. dependency licenses reviewed
6. repository history checked for copied/incompatible code
7. ECA final text reviewed/activated
8. entity ECA path exists
9. DCO process activated
10. contributor guide explains licensing plainly
11. TRADEMARKS.md published
12. third-party notice mechanism exists
13. substantial external PR merges blocked until ECA/DCO checks pass
```

Public **viewing** can occur before every commercial instrument exists.

Public **merging of substantial outside code** should not.

---

# 87. Pre-Commercial-License Gate

Before selling the first proprietary exception:

```text
1. establish correct contracting entity
2. identify exact covered components
3. prove rights chain for every covered component
4. exclude third-party code Evrosion cannot relicense
5. lawyer reviews commercial license
6. Foundation/company rights model documented
7. trademark/certification terms separated
8. security-update rights clarified
9. support/SLA terms separated
10. export/tax/jurisdiction obligations reviewed
```

Never sell rights the project does not actually own/control.

---

# 88. Pre-0.9 Brand Gate

Before consumer-scale public branding:

```text
1. professional trademark clearance
2. prioritize relevant registration jurisdictions/classes
3. register EVROSION when financially practical
4. protect logo separately where appropriate
5. define EVROSION CERTIFIED mark
6. Foundation ownership/stewardship path confirmed
7. trademark-use policy finalized
8. fork/compatibility wording examples published
```

The exact filing strategy depends on budget and jurisdiction.

---

# 89. Final Recommendation

The best current fit for Evrosion is:

```text
EVROSION CORE
GPL-3.0-only
+
commercial alternative license

PUBLIC SDK / DRIVER / ABI BOUNDARY
Apache-2.0

DOCUMENTATION
CC-BY-4.0

CONTRIBUTIONS
Contributor retains copyright
+
Evrosion Contributor Agreement
+
DCO provenance sign-off

IDENTITY
Separate trademark + certification policy

FUTURE STEWARDSHIP
Foundation protects open-core continuity and brand
Company commercializes services/exceptions
```

This structure gives Evrosion all four things it needs simultaneously:

```text
REAL OPEN SOURCE
OWNER FREEDOM
COMMERCIAL SUSTAINABILITY
THIRD-PARTY ECOSYSTEM FREEDOM
```

None needs to be sacrificed to obtain the others.

---

# 90. Final Principle

> **Evrosion's code should be free enough that nobody can take the operating system away from its users, structured enough that application and hardware ecosystems can grow without legal contamination, and controlled clearly enough that companies wanting proprietary rights can fund the project instead of silently privatizing the commons.**

---

# R-006 COMPLETE — LICENSING, CONTRIBUTOR RIGHTS & TRADEMARK DIRECTION LOCKED
