Public technical edition. Editorial changes remove development-workspace instructions; technical requirements and clause identities remain. The source map records actual edition hashes.

# Evrosion R-005 — Public Release Strategy, GitHub-Only Launch & Community Growth

**Status:** ACCEPTED DESIGN DIRECTION  
**Series:** R — Release, Project & Sustainability  
**Decision:** R-005  
**Purpose:** Define when Evrosion becomes public, what its early releases mean, how the project attracts its first contributors and testers, how GitHub functions as the entire public home until approximately 0.9, and how Evrosion avoids both premature consumer hype and contributor starvation.

> **Core rule:** Develop in public early, but never pretend unfinished development milestones are consumer-ready releases.

---

# 1. Strategic Position

Evrosion must solve two different problems:

1. **Make development visible early enough to attract talented people.**
2. **Avoid presenting an unfinished operating system as a finished consumer product.**

These are not opposites.

Evrosion can be publicly developed, publicly cloned, publicly tested, and publicly discussed long before it is ready to replace someone's everyday operating system.

The project should therefore distinguish:

```text
PUBLIC DEVELOPMENT
```

from:

```text
CONSUMER-READY RELEASE
```

---

# 2. GitHub Is the Entire Public Home Until ~0.9

Until approximately the 0.9 / serious pre-release stage, Evrosion should not maintain a separate project website.

The canonical public home is the official Evrosion GitHub organization/repository.

GitHub hosts:

- source code;
- README/project introduction;
- architecture documentation;
- contribution documentation;
- issues;
- pull requests;
- security policy;
- releases/downloads;
- roadmaps/milestones;
- Discussions/community;
- announcements;
- changelogs;
- public project governance documents.

No separate forum, Discord, Matrix, website, newsletter platform, or documentation site is required initially.

External communities may be used for **outreach**, but they link back to GitHub.

At approximately 0.9, Evrosion may create a dedicated website because ordinary users will then need a simpler consumer-facing experience than a source repository.

---

# 3. When the Repository Becomes Public

Preferred launch point:

> **Make the main Evrosion repository public once M0 is genuinely complete and the public-repo prerequisites are ready.**

M0 completion means Evrosion has moved beyond pure scaffolding and can demonstrate a real boot path.

The handoff-defined M0 target remains:

```text
ev bootstrap
ev build
ev run
ev debug kernel

x86-64
UEFI
QEMU
serial output
panic output
symbolized debugging
framebuffer handoff
repeatable image generation
```

A minimal successful proof such as:

```text
Evrosion kernel entered.
```

is enough for M0.

The repository does not need to wait for 0.1 before becoming public.

The point of M0 publication is:

> **Show that Evrosion is a real operating-system implementation, not merely an architecture proposal.**

---

# 4. Preconditions Before Making the Repository Public

Before switching the main repository to public, complete a deliberate publication checklist.

## Required

- open-source license selected and committed;
- contribution/legal model sufficiently settled for outside code;
- repository history checked for secrets/tokens/private credentials;
- no personal/private material unintentionally committed;
- `README.md`;
- `CONTRIBUTING.md`;
- `SECURITY.md`;
- `CODE_OF_CONDUCT.md` or equivalent community behavior rules;
- architecture index / invariants available;
- working build instructions;
- supported host/toolchain requirements documented;
- issue templates/forms;
- pull-request template;
- public project status clearly marked;
- security-reporting channel exists;
- branch/ruleset protection configured;
- release/signing process appropriate to current maturity documented.

## Recommended

- `CODEOWNERS` once there are enough maintainers for it to be meaningful;
- GitHub Discussions enabled;
- repository topics configured for discovery;
- architecture diagram;
- short boot/demo recording;
- milestone/project board;
- clearly labeled starter contribution paths.

---

# 5. The README Is the Early Evrosion Homepage

Because there is no website, the root `README.md` must function as the project's front page.

A visitor should understand Evrosion within roughly 30 seconds.

Recommended order:

## 1. Name + one-line identity

> **Evrosion — a new capability-based operating system built from scratch around simplicity, owner sovereignty, recovery, and progressive responsibility.**

## 2. Current status

Example:

```text
Status: Early development / M0
Target: x86-64 + UEFI + QEMU/KVM
Not ready for daily use
```

## 3. Why Evrosion exists

Short statement of the core philosophy:

- simple by default;
- full capability preserved;
- owner controls the machine;
- safe defaults without paternalistic lockout;
- local/offline capable;
- recovery-first.

## 4. What already works

Never claim planned features as implemented features.

## 5. What does not work yet

Be brutally honest.

## 6. Quick start

Ideally the path eventually becomes approximately:

```bash
git clone <official-repository>
cd evrosion
./ev bootstrap
./ev build
./ev run
```

The exact commands are governed by E-014.

## 7. Short demonstration

A compact GIF/video/screenshot showing the current milestone.

## 8. Architecture highlights

Only the handful of concepts that make the project unusual.

Link to full architecture documents instead of pasting E-001–E-026 into the README.

## 9. Contributing

One paragraph + link to `CONTRIBUTING.md`.

## 10. Security

Link to `SECURITY.md`.

## 11. License

Clear and visible.

---

# 6. The README Must Not Become the Architecture Bible

The README is an onboarding surface, not a storage dump.

Do not paste the entire Evrosion constitution into it.

Use layered documentation:

```text
README
  ↓
START_HERE / developer overview
  ↓
architecture index
  ↓
specific E-/X-/R-documents
  ↓
implementation code/tests
```

This reduces cognitive load for new contributors and reduces unnecessary AI/context consumption for development tools.

---

# 7. GitHub Organization vs Personal Repository

Once public development begins, Evrosion should preferably live under an official GitHub organization rather than remain permanently attached to one personal account.

Benefits:

- cleaner project identity;
- multiple repositories later without fragmentation;
- teams/permissions;
- organization Discussions if needed;
- clearer transition to future Foundation stewardship;
- less dependence on one personal account.

Founder control remains intact under R-002.

Creating an organization does **not** imply giving governance away.

---

# 8. Protect the Main Branch From Day One

Public visibility increases both contribution opportunity and attack surface.

At minimum, the primary branch should use GitHub branch protections/rulesets appropriate to project size.

Early project:

- block force-pushes to the canonical main branch;
- block accidental deletion;
- require CI/status checks where they exist;
- route outside contributions through pull requests;
- restrict direct pushes to trusted maintainers/founder.

When enough reviewers exist:

- require review for security-sensitive areas;
- require Code Owner review where appropriate;
- dismiss/refresh approvals when the actual diff materially changes.

The founder may retain emergency/admin bypass during the founder era.

---

# 9. Public Development Milestones vs Releases

Evrosion should not call every milestone a release.

## M0–M4

These are primarily **development milestones**.

They may have:

- Git tags;
- signed development snapshots;
- demonstration builds;
- GitHub announcements.

But they are not marketed as consumer OS releases.

## M5 / Evrosion 0.1

This becomes the first major formal public Developer Preview.

M6 and later development continue from there.

---

# 10. Evrosion 0.1 — Developer Preview

Official name/positioning:

> **Evrosion 0.1 — Developer Preview**

Primary audience:

- operating-system developers;
- Rust developers;
- security researchers;
- systems programmers;
- early contributors;
- technical enthusiasts.

Primary supported environment:

```text
x86-64
UEFI
QEMU/KVM
```

Evrosion 0.1 must **not** be marketed as a normal daily-driver operating system.

---

# 11. The 0.1 Promise

0.1 should prove the architectural spine already defined by E-025.

The target remains conceptually:

```text
ev run
→ UEFI/QEMU boot
→ kernel
→ Root Supervisor
→ isolated userspace services
→ capability IPC
→ persistent storage
→ graphical shell
→ input
→ Hello.zion
→ trusted file picker
→ scoped file grant
→ deliberate app crash
→ shell survives
→ structured crash record
→ app restarts
→ deliberately broken System Generation
→ rollback to Known Good
```

This demonstration is the primary 0.1 recruiting artifact.

It shows why Evrosion is technically interesting before the OS is broadly useful.

---

# 12. 0.1 Must Explicitly Warn About Its Limits

The GitHub Release and README should say plainly:

> **Developer Preview. Not intended for normal daily use or important data. Primary target is QEMU/KVM. Real hardware is experimental unless explicitly stated otherwise.**

This prevents hype from creating false expectations.

A project earns trust by accurately stating limitations.

---

# 13. Releases Between 0.1 and 0.9

Do not pre-lock an artificial mapping such as:

```text
0.2 = networking
0.3 = AMD
0.4 = NVIDIA
0.5 = compatibility
```

years in advance.

Instead:

- publish current milestone;
- publish next milestone;
- publish broad longer-term direction;
- allow implementation evidence to determine numbering and sequencing.

0.x versions may steadily expand:

- networking;
- hardware support;
- drivers;
- installer;
- applications;
- graphical maturity;
- package ecosystem;
- developer platform;
- real-machine reliability.

But specific future release-number promises remain flexible.

---

# 14. What 1.0 Means

Reserve Evrosion 1.0 for the first release the project is comfortable recommending to ordinary users on explicitly supported hardware.

1.0 does **not** mean:

- every planned feature exists;
- every PC is supported;
- architecture is frozen forever;
- compatibility is perfect.

It means approximately:

> **Evrosion has crossed from operating-system experiment into an operating system a normal person can reasonably install and use on supported hardware.**

The exact 1.0 acceptance contract should be written later, after experience from 0.x.

---

# 15. Release Version Is Not API Version

Human release versions such as:

```text
0.1
0.8
1.0
2.0
```

are not developer compatibility contracts.

E-026 already separates:

- Release;
- System Generation;
- Platform API Level;
- contract version;
- ABI fingerprint;
- package version;
- state schema epoch.

Do not overload the human marketing release number.

---

# 16. Quality-Driven Release Cadence

Evrosion releases when release criteria pass.

Do not create a dangerous rule such as:

> “0.3 must ship on October 1 regardless of state.”

Public progress can continue between releases through:

- commits;
- milestones;
- Discussions announcements;
- development snapshots;
- changelogs.

Formal release quality is more important than arbitrary calendar promises.

---

# 17. Published Release Artifacts Are Historical Objects

Never silently replace the bytes of an existing formal release while keeping the same release identity.

If a release needs correction:

```text
0.2 → 0.2.1
```

or another distinct release/System Generation.

Where practical, use GitHub's immutable-release capability for formal public releases so tags/assets cannot be silently replaced after publication.

GitHub's current immutable-release feature locks release tags/assets and automatically creates a cryptographically verifiable release attestation.

Evrosion's own R-003 release trust remains authoritative; GitHub's feature is an additional defense.

---

# 18. GitHub Build/Release Attestations Are Supplemental

GitHub Actions can generate artifact attestations linking an artifact to repository/workflow/commit information and publish them through Sigstore-backed transparency infrastructure for public repositories.

Evrosion may use these as extra public provenance.

They do **not** replace:

- Evrosion's official signing hierarchy;
- reproducible-build verification;
- R-003's update trust;
- independent rebuilders.

They are another useful proof layer.

---

# 19. GitHub Discussions Is the Early Community Forum

Enable GitHub Discussions instead of launching another communication platform.

Recommended minimal categories:

- **Announcements**
- **Development**
- **Ideas**
- **Help / Q&A**
- **Show & Tell**

Issues remain for actionable work.

Pull requests remain for proposed code/document changes.

Discussions remain for broader conversation.

This keeps the entire public project searchable and attached to the repository.

---

# 20. Do Not Create Ten Community Platforms

Before 0.9, avoid splitting people across:

- Discord;
- Matrix;
- Slack;
- forum;
- Reddit community;
- mailing list;
- standalone website comments;
- separate wiki.

Fragmentation is especially harmful when the community is small.

If a synchronous chat becomes genuinely necessary later, add it because there is demonstrated demand, not because open-source projects are expected to have one.

---

# 21. External Outreach Is Allowed Without External Project Infrastructure

GitHub is the project home.

Evrosion may still announce meaningful milestones in places where relevant technical people already gather.

Examples:

- OSDev.org announcement/test-request forums;
- Hacker News / Show HN when there is a genuinely demonstrable milestone;
- relevant OS-development communities;
- relevant Rust/systems communities;
- relevant security communities;
- relevant Reddit communities such as OS development communities.

Outreach message:

> **Here is something real. Here is what it does. Here is what does not work. Here is the GitHub repo.**

Do not spam every incremental commit across external communities.

---

# 22. 0.1 Community Goal Is Not User Count

0.1 is not optimized for millions of downloads.

The primary community success metric is:

> **Find the first small group of technically strong recurring contributors.**

A realistic early ambition is not:

```text
1,000,000 users
```

but:

```text
5 recurring contributors
→ 20
→ 50
```

A handful of excellent systems contributors is enormously valuable during an OS project's early years.

---

# 23. Contributor Funnel

Evrosion should deliberately reduce friction through a sequence:

```text
DISCOVER
→ UNDERSTAND
→ BUILD
→ RUN
→ FIND SOMETHING
→ DISCUSS
→ SUBMIT
→ REVIEW
→ RETURN
→ BECOME MAINTAINER
```

Most contribution failures happen because somebody falls out of this funnel.

R-005 therefore treats contributor experience as engineering work.

---

# 24. “Time to First Boot” Is a Critical Community Metric

For a systems project, the first successful build/run is one of the largest onboarding barriers.

The development UX should aggressively minimize:

```text
fresh supported Linux host
→ clone
→ bootstrap
→ build
→ ev run
→ Evrosion boots
```

`ev bootstrap` should diagnose missing prerequisites where possible.

`ev doctor` should eventually explain broken host configuration.

A developer who spends six hours fighting undocumented host dependencies may never return.

---

# 25. Documentation Is Recruitment Infrastructure

Open Source Guides explicitly identifies clear documentation and easy first wins as critical to reducing contributor friction.

Evrosion documentation should answer:

- what the project is;
- how to build it;
- how to run it;
- where components live;
- how to debug it;
- how to test changes;
- what architecture laws must be preserved;
- where to ask before making a large change.

A contributor should not need private access to the founder to understand the repository.

---

# 26. Contribution Is Bigger Than Kernel Code

Evrosion should explicitly welcome useful work from:

- kernel developers;
- Rust programmers;
- driver developers;
- security researchers;
- testers;
- UI/UX designers;
- accessibility specialists;
- technical writers;
- documentation contributors;
- translators;
- hardware testers;
- graphics/audio developers;
- tooling developers;
- `.zion` application developers;
- performance engineers.

This dramatically expands the useful contributor pool.

---

# 27. Starter Contributions — Use a Hybrid Approach

Maintain a **small** number of genuinely good newcomer tasks.

GitHub surfaces repositories/issues carrying the `good first issue` label and may increase their discoverability.

Useful labels may include:

```text
good first issue
help wanted
kernel
drivers
security
docs
tests
tooling
graphics
storage
performance
architecture
```

However, do not create a giant curated starter backlog.

SerenityOS eventually reduced reliance on curated `good first issue` lists because maintaining them cost time and self-discovered problems often produced more engaged contributors.

Evrosion should therefore say:

> Here are a few safe starting points. Also build Evrosion, play with it, find something that bothers you, and propose a fix.

---

# 28. First Contributions Should Usually Be Small

A first-time contributor should generally not begin by:

- replacing the scheduler;
- adding an entirely new package manager;
- introducing a new subsystem;
- rewriting the capability model.

SerenityOS similarly recommends new contributors begin with smaller changes to learn project direction/process before attempting large components.

Evrosion should encourage:

```text
small correct contribution
→ learn review/testing
→ establish trust
→ larger responsibility
```

Large architecture-affecting changes should begin with an Issue/Discussion/ADR proposal.

---

# 29. Contribution accountability

Every submitter must understand the change, its architecture and provenance,
answer review questions, run appropriate tests, address problems and remain
accountable for the submitted material. Tool output is not a substitute for
understanding or evidence. Evaluation concerns quality and rights, not a claim
that one particular authorship method was used.

---

# 30. Contribution quality

Evrosion may reject contributions that appear to be:

- mass-generated without understanding;
- untested;
- unrelated to existing architecture;
- hundreds of speculative files;
- generated documentation that contradicts canonical architecture;
- issue spam;
- PR spam;
- generated benchmark/security claims without evidence.

The project evaluates **quality and accountability**, not whether a tool was used.

OpenSSF's 2026 guidance similarly recommends that open-source projects explicitly document AI contribution expectations and create guardrails rather than assuming AI use can always be detected or universally prohibited.

---

# 31. Pull Request Requirements

Keep PR requirements short enough that contributors actually read them.

A PR should normally answer:

```text
What changed?
Why?
How was it tested?
What architecture/contracts does it touch?
Are there known limitations?
```

If AI materially assisted the implementation, the contributor should still certify:

> **I reviewed and understand the submitted change and take responsibility for it.**

Exact AI-disclosure wording may be adjusted later.

---

# 32. Issue Forms Should Generate Actionable Reports

GitHub issue forms/templates can require structured information.

Useful initial forms:

## Bug

- current commit/release;
- host environment;
- `ev` command;
- expected behavior;
- actual behavior;
- logs/Failure Capsule where safe;
- reproduction steps.

## Feature / improvement

- problem;
- proposed user outcome;
- relevant architecture;
- alternatives considered.

## Hardware report

Later:

- hardware identifiers;
- boot result;
- working components;
- broken components;
- firmware version;
- logs.

Security vulnerabilities must redirect to `SECURITY.md`, not public Issues.

---

# 33. Community Hardware Reports Are Not Certification

As real-hardware experiments begin, maintain a public compatibility database or structured issues.

States may include:

```text
WORKS
WORKS WITH LIMITATIONS
EXPERIMENTAL
UNSUPPORTED
KNOWN BROKEN
```

A community report:

> “Evrosion booted on my ThinkPad.”

does **not** mean:

> “All ThinkPads are officially supported.”

Evrosion Certified remains a separate formal program.

---

# 34. Public Roadmap

Keep the roadmap small.

Show:

- current milestone;
- next milestone;
- near-term objectives;
- long-term direction.

Do not publish hundreds of promises with speculative dates.

The project already has an architecture-complete plan.

Public roadmap content should explain implementation progress, not reopen E-001–E-026.

---

# 35. Progress Updates

While GitHub is the only home, publish project updates through GitHub Discussions announcements.

A useful update format:

```text
Evrosion Development Update

Completed
- ...

Working
- ...

Broken / discovered
- ...

Next
- ...

Help wanted
- ...
```

Consistent visible progress signals that the project is alive.

Do not promise daily/weekly updates if that schedule itself becomes burdensome.

---

# 36. Show Running Software, Not Architecture Slides

The strongest 0.1 recruiting content is the system actually working.

Examples:

- boot from UEFI;
- Root Supervisor startup;
- multiple userspace services;
- capability denial/transfer;
- graphical shell;
- `Hello.zion`;
- trusted picker;
- crash app;
- shell survives;
- automatic rollback.

A 60–120 second demonstration of this sequence is more persuasive than pages of claims.

Architecture docs remain available for people who want the depth.

---

# 37. Every Formal Release Must Answer Five Questions

At the top of the GitHub Release:

1. **Who is this for?**
2. **What works?**
3. **What does not work?**
4. **Where is it supported/safe to run?**
5. **How do I report a problem?**

Then include:

- release notes;
- known issues;
- source revision;
- hashes/signatures/provenance;
- upgrade instructions;
- rollback considerations.

---

# 38. Public Tone

Evrosion should be ambitious without making unsupported claims.

Good:

> “Evrosion is building a different operating-system model around owner sovereignty, capability security and recovery.”

Bad:

> “Windows/macOS are dead. Evrosion is already better.”

Let running code earn credibility.

Do not start fights with incumbent projects for attention.

Technical comparison is fine; tribal marketing is not useful.

---

# 39. Community Conduct

Early project spaces should remain focused on building Evrosion.

Community rules should require:

- respectful technical disagreement;
- no harassment;
- no brigading;
- no spam;
- no malicious disruption;
- no unrelated ideological fights in project spaces.

People can disagree aggressively about technical decisions.

Attack ideas/code, not people.

---

# 40. Maintainer Growth

Do not hand write/merge access to someone because they are enthusiastic for one week.

Trust emerges from sustained work.

Potential progression:

```text
user
→ contributor
→ recurring contributor
→ subsystem contributor
→ reviewer
→ maintainer
```

Maintainer status should reflect demonstrated:

- technical competence;
- architectural understanding;
- reliability;
- review quality;
- community behavior;
- sustained responsibility.

Exact formal process belongs to later governance maturity.

---

# 41. Avoid Founder Bottleneck

During early development the founder remains final authority, but the public project must gradually make routine contribution possible without requiring founder explanation for everything.

Countermeasures:

- architecture documentation;
- code ownership boundaries;
- tests;
- issue templates;
- review guidelines;
- maintainers;
- ADR process.

The founder should increasingly decide **important direction**, not manually answer every build question forever.

---

# 42. Metrics That Actually Matter

Avoid optimizing for vanity metrics alone.

GitHub stars are useful visibility but not project health.

Better early measures include:

- recurring contributors;
- contributor retention;
- time from clone to first successful `ev run`;
- issue response quality;
- accepted contributions;
- number of independent successful builds;
- independent reproducibility checks;
- security reports;
- hardware reports later;
- number of people capable of reviewing core areas.

No OS telemetry is required to measure these.

---

# 43. Growth Stages

## 0.1 — Find Builders

Target:

- OS developers;
- Rust/system developers;
- security researchers;
- technically curious contributors.

Success:

> people build Evrosion and begin improving it.

## 0.2–0.4 — Find Testers

Target expands toward:

- QEMU testers;
- subsystem developers;
- early hardware experimenters;
- driver contributors.

## 0.5–0.7 — Find Enthusiasts

People begin interacting with Evrosion as a system rather than merely as source code.

## 0.8–0.9 — Find Early Users

Project begins preparing:

- polished installer;
- broader supported hardware;
- more complete desktop;
- website;
- consumer documentation;
- clearer support expectations.

## 1.0 — Find Ordinary Users

Evrosion is recommendable on defined supported hardware.

These are audience shifts, not hard feature contracts.

---

# 44. No Website Until ~0.9

This is a locked R-005 project decision.

Before approximately 0.9:

```text
GitHub = Evrosion public HQ
```

At/near 0.9, reassess creation of:

- official website;
- simple download flow;
- consumer documentation;
- certification pages;
- public support information;
- normal-user onboarding.

The website should appear because users need it, not because a project is expected to own a domain on day one.

---

# 45. External Outreach Plan for 0.1

When 0.1 launches, perform a deliberate one-time technical launch.

Prepare:

- strong README;
- clear Release page;
- 60–120 second demo;
- architecture summary;
- “why Evrosion” paragraph;
- quick build/run instructions;
- explicit limitations;
- “help wanted” section.

Then announce selectively to relevant technical communities.

Potential destinations include:

- OSDev.org's announcement/test-request space;
- Hacker News when there is a real demonstration;
- relevant OS/system-development communities;
- Rust systems communities;
- security communities;
- relevant Reddit communities.

The objective is **not mass consumer advertising**.

The objective is:

> **put working Evrosion in front of people capable of helping build it.**

---

# 46. Outreach Frequency

Do not promote every commit externally.

Useful external moments:

- public M0 proof;
- 0.1 Developer Preview;
- major graphical milestone;
- first real-hardware milestone;
- major security/recovery demonstration;
- 0.9 pre-release;
- 1.0.

Between those events, GitHub activity speaks for itself.

---

# 47. Downloads

Before the website exists, formal binaries/images are distributed through official GitHub Releases and authenticated according to R-003.

Source development continues directly from the repository.

Do not attach random binaries to Issues/Discussions and call them official releases.

Development artifacts should be clearly marked as such.

---

# 48. Release Immutability

For formal GitHub releases, prefer GitHub's immutable release mode where compatible with the Evrosion release workflow.

Current GitHub behavior locks:

- release tag;
- release assets;

after publication and produces a release attestation.

Release notes may still be corrected without replacing the underlying artifact.

Evrosion should still independently sign/authenticate releases under R-003.

---

# 49. Avoid Fork Confusion

Forking is welcome.

But unofficial forks must not impersonate the official project.

The official GitHub organization, trademark policy, and R-003 signatures distinguish:

```text
Official Evrosion
```

from:

```text
Evrosion-derived fork
```

Forks should be free to differentiate themselves while following the eventual license/trademark rules.

---

# 50. Architecture Changes From Contributors

E-001–E-026 are already complete.

Public contribution does not mean every pull request gets to reopen the architecture.

Changes conflicting with locked invariants require:

- implementation evidence showing a real contradiction/problem;
- explicit architectural discussion;
- ADR/change process;
- founder approval during founder era.

Otherwise:

> preserve the architecture and build.

---

# 51. Security Contributions

Researchers should follow R-004.

Never ask researchers to publicly disclose a vulnerability in Issues for community visibility.

Security bugs use private reporting.

Normal security-hardening improvements that expose no active vulnerability may use ordinary PR/Issue flow.

---

# 52. Contribution Licensing

Do not accept substantial outside contributions before R-001/R-002's deferred licensing/contributor-rights mechanism is actually implemented.

Public visibility may occur before accepting all classes of contributions if necessary, but merge policy must be legally clear.

Once contributions are open, contributors should know exactly:

- project license;
- contribution license/grant;
- whether CLA/DCO applies;
- copyright ownership;
- contribution quality and provenance expectations.

---

# 53. Support Expectations

Early open development does not create an unlimited support obligation.

For 0.x Developer Preview stages:

- Issues are for reproducible bugs and project work;
- Discussions/Q&A handle general questions;
- build support is best-effort;
- unsupported host/hardware configurations may be closed or redirected;
- volunteers/maintainers are not obligated to debug every individual's custom environment.

This prevents the project from drowning in support before it has staff.

---

# 54. Anti-Spam / Moderation

Public launch will eventually attract:

- bot-created issues;
- duplicated questions;
- unreviewed bulk PRs;
- feature spam;
- low-effort architecture rewrites;
- malicious reports.

The project may:

- close duplicates;
- require issue templates;
- rate-limit participation where GitHub permits;
- lock bad-faith threads;
- ban abusive accounts;
- require concrete reproduction/evidence;
- reject code without adequate explanation, tests and provenance.

Community openness does not mean accepting unlimited maintainer workload.

---

# 55. Contributor Retention Matters More Than Contributor Count

A flood of one-off typo PRs can make a repository look active without building an OS.

Evrosion should value people who:

- understand the architecture;
- return;
- review others;
- own difficult components;
- improve documentation/tests;
- accept responsibility.

Community success is measured by durable capability, not raw PR count.

---

# 56. Adversarial Review

## Failure: Public too early, repo looks like vaporware
**Resolution:** public launch at completed M0, when the OS demonstrably boots.

## Failure: Wait until 1.0, no contributors arrive
**Resolution:** public development starts around M0, long before consumer readiness.

## Failure: People mistake 0.1 for daily-driver OS
**Resolution:** 0.1 is explicitly “Developer Preview,” QEMU-first, with strong limitation text.

## Failure: Website/community infrastructure consumes founder time
**Resolution:** GitHub-only until approximately 0.9.

## Failure: New developer cannot build the project
**Resolution:** `ev bootstrap/build/run`, `ev doctor`, tested build docs, CI.

## Failure: README overwhelms visitors with 26 architecture documents
**Resolution:** short README → layered docs → architecture index.

## Failure: Nobody knows how to help
**Resolution:** contribution guide, small starter-task pool, labels, clear subsystem map.

## Failure: Maintaining starter tasks becomes its own job
**Resolution:** keep only a small curated pool; encourage contributors to discover real problems.

## Failure: Low-quality PR spam consumes maintainers
**Resolution:** Contributors must understand, test, explain and take responsibility for submitted changes; reject unreviewed dumps.

## Failure: GitHub account compromise mutates historic release
**Resolution:** immutable formal releases where possible + R-003 independent release signing/provenance.

## Failure: Main branch gets vandalized/force-pushed
**Resolution:** branch/ruleset protection, restricted pushes, required checks/reviews as staffing permits.

## Failure: Ten external community platforms fragment the project
**Resolution:** GitHub Discussions as the only official community forum until demonstrated need.

## Failure: Hype outpaces reality
**Resolution:** public releases always state exactly what works, what fails, and who should use them.

## Failure: Community hardware success is mistaken for certification
**Resolution:** community compatibility and Evrosion Certified remain separate.

## Failure: Project optimizes for stars instead of engineering depth
**Resolution:** recurring contributors, build success, reviews, tests and subsystem ownership are primary health metrics.

## Failure: Founder becomes support desk for every contributor
**Resolution:** docs, automated tooling, maintainers, Discussions, issue templates and architecture index.

## Failure: Public contributors casually redesign Evrosion
**Resolution:** locked architecture remains authoritative unless implementation evidence justifies formal change.

---

# 57. Research Basis / Precedents

## GitHub Community Profiles / README

GitHub recommends community health files including README, LICENSE, CONTRIBUTING and CODE_OF_CONDUCT, and describes the README as the normal first surface explaining what a project does, why it is useful, how to get started and where to get help.

https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories

https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes

## GitHub Discussions

GitHub Discussions supports announcements, Q&A, ideas, polls and open-ended community conversation directly beside a repository.

https://docs.github.com/en/discussions/collaborating-with-your-community-using-discussions/about-discussions

## GitHub Topics

Repository topics improve discovery by subject area and help users find projects to contribute to.

https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics

## GitHub Contribution Labels

GitHub can surface issues marked `good first issue` to people looking for approachable contributions.

https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/encouraging-helpful-contributions-to-your-project-with-labels

## Open Source Guides

Open Source Guides recommends reducing friction across the contributor journey, beginning with clear documentation and easy ways to use and contribute to the project.

https://opensource.guide/building-community/

## SerenityOS

SerenityOS encourages new contributors to start small and learn project process. In 2026, SerenityOS also explained why it reduced reliance on curated “good first issue” lists: maintenance cost and higher engagement from contributors who discover their own real problems.

https://github.com/SerenityOS/serenity/blob/master/CONTRIBUTING.md

https://github.com/SerenityOS/serenity/issues/26771

## Ladybird

Ladybird publicly labels itself pre-alpha/developer-only and provides clear build/get-involved documentation. In June 2026 it stopped accepting code from non-maintainers after AI dramatically changed the economics of public code submissions, while still welcoming bug reports/testing/security/technical feedback. Evrosion should learn from the spam problem without copying the maintainer-only contribution model.

https://github.com/LadybirdBrowser/ladybird

https://ladybird.org/posts/changing-how-we-develop-ladybird/

## OpenSSF — AI-era open source

OpenSSF's 2026 guidance recommends maintainers establish explicit AI contribution expectations and guardrails instead of assuming AI use can always be identified or categorically avoided.

https://openssf.org/wp-content/uploads/2026/05/Securing-Open-Source-in-the-Age-of-AI.pdf

## GitHub Rulesets / CODEOWNERS

GitHub supports rulesets/branch protections requiring pull requests, passing status checks, reviews, Code Owner approvals and force-push restrictions.

https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets

https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

## GitHub Immutable Releases

GitHub immutable releases can lock release tags/assets after publication and automatically generate release attestations.

https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases

## GitHub Artifact Attestations

GitHub can generate cryptographically signed provenance for public build artifacts using Sigstore-backed attestations.

https://docs.github.com/en/actions/concepts/security/artifact-attestations

## OSDev.org

OSDev.org maintains active OS-development, OS-design and announcement/test-request forums, making it a relevant technical outreach location for real milestones.

https://forum.osdev.org/

---

# 58. Locked R-005 Laws

1. **GitHub is Evrosion's entire official public home until approximately 0.9/pre-release.**
2. **No dedicated Evrosion website is required before ~0.9.**
3. **The main source repository should become public after M0 is genuinely complete and public-repo legal/security prerequisites are ready.**
4. **M0–M4 are public development milestones, not consumer releases.**
5. **Evrosion 0.1 is positioned as an Official Developer Preview.**
6. **0.1's primary supported target is x86-64 + UEFI + QEMU/KVM.**
7. **0.1 is explicitly not marketed for normal daily use or important data.**
8. **The canonical 0.1 value proposition is the working architectural proof defined by E-025.**
9. **0.x release numbering remains implementation-driven rather than pre-promised years ahead.**
10. **1.0 is reserved for the first release recommendable to ordinary users on explicitly supported hardware.**
11. **Release number remains separate from Platform API/contract/ABI identities.**
12. **Formal releases are quality-driven, not forced by arbitrary calendar deadlines.**
13. **Formal published release artifacts are immutable historical objects; corrected builds receive new identities.**
14. **The GitHub README serves as the early project homepage and must stay concise/layered.**
15. **GitHub Discussions is the primary official community forum before ~0.9.**
16. **Issues are for actionable work; Discussions are for broad conversation; PRs are for changes.**
17. **External technical communities may be used for selective outreach while GitHub remains the canonical project home.**
18. **The primary 0.1 community objective is attracting recurring builders/contributors, not mass user adoption.**
19. **Time-to-first-successful `ev run` is a critical contributor-experience metric.**
20. **Contribution opportunities include code, security, testing, docs, accessibility, design, translation, hardware testing, performance and applications.**
21. **Maintain only a small useful starter-task pool; also encourage contributors to discover/fix real issues.**
22. **First-time contributors should generally start small before owning large architecture-affecting changes.**
23. **Submitted changes require understanding, testing, provenance and accountability.**
24. **Low-effort issue/PR/code dumps may be rejected.**
25. **Outside contributors may not casually reopen E-001–E-026 without implementation evidence and formal architecture process.**
26. **The primary branch is protected with GitHub rules appropriate to project maturity.**
27. **Formal GitHub releases should use immutable release/tag/asset protections where compatible with R-003.**
28. **GitHub release/artifact attestations may supplement but never replace Evrosion's own release-trust system.**
29. **Community hardware reports never imply formal Evrosion hardware certification.**
30. **Project health is measured primarily through recurring contributors, successful builds, review capacity, test quality and subsystem ownership—not stars alone.**
31. **Support expectations remain best-effort during early Developer Preview stages.**
32. **Security reports use R-004's private process, never ordinary public Issues.**
33. **Substantial external contributions must not be merged until the contribution licensing/legal mechanism is actually in place.**
34. **A dedicated website and broader consumer-facing launch infrastructure are reconsidered around 0.9.**
35. **Public claims must describe running reality, not future architecture as if it already exists.**

---

# 59. Immediate M0 → Public Repository Checklist

Because Evrosion's first bootable instance is now approaching, the practical next-publication sequence is:

```text
1. Complete M0 acceptance test
2. Freeze/record exact first successful boot revision
3. Select final public source license / contributor mechanism
4. Scrub repository history for secrets/private data
5. Create official GitHub organization
6. Move/create canonical repository under organization
7. Add README.md
8. Add CONTRIBUTING.md
9. Add SECURITY.md
10. Add CODE_OF_CONDUCT.md
11. Add LICENSE
12. Add issue forms + PR template
13. Enable Discussions
14. Configure repository topics
15. Configure main-branch ruleset/protection
16. Make build/run instructions reproducible
17. Record short M0 boot demonstration
18. Publish repository
19. Announce M0 selectively to OS-development communities
20. Continue toward 0.1 Developer Preview
```

Do **not** rush step 18 merely because M0 boots.

The public repo should open cleanly.

---

# 60. Immediate 0.1 Launch Checklist

When E-025's 0.1 proof is complete:

```text
1. Run full 0.1 acceptance path
2. Run architecture fitness tests
3. Reproduce canonical release build independently
4. Generate provenance
5. Sign under R-003
6. Publish immutable GitHub Release where appropriate
7. Record full 0.1 demonstration
8. Publish concise release notes
9. Publish exact supported target
10. Publish exact limitations
11. Mark real hardware experimental unless specifically validated
12. Identify 5–15 useful help-wanted areas
13. Post GitHub Announcement
14. Announce selectively to relevant technical communities
15. Triage incoming bugs/contributions aggressively but respectfully
16. Measure recurring contributors rather than raw traffic
```

---

# 61. Final Principle

> **At 0.1, Evrosion does not need millions of users. It needs proof, credibility, and the first handful of people talented enough to help turn a bootable architecture into a real operating system. GitHub should make it immediately obvious what Evrosion is, what actually works, how to run it, and where a capable person can make it better.**

---

# R-005 COMPLETE — PUBLIC RELEASE & COMMUNITY-GROWTH DIRECTION LOCKED
