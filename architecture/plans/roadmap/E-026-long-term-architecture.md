# Evrosion — E-026 Long-Term Architecture

**Status: ARCHITECTURAL DIRECTION DECIDED AND CLOSED**

Evrosion will evolve through an:

> **Evolutionary Platform Architecture with Stable Laws, Replaceable Implementations, Compatibility Windows, Side-by-Side Migration, and Architecture Fitness Governance**

E-026 is the long-term architectural constitution for Evrosion.

Its purpose is to make sure that Evrosion can grow for years without losing the principles established in E-001 through E-025.

The central rule is:

> **Freeze the laws that make Evrosion Evrosion. Keep implementations replaceable.**

A second rule follows directly:

> **Freeze contracts, not internals.**

---

# E-026.1 — Stable Laws, Replaceable Implementations

The following ideas should remain exceptionally stable:

```text
owner sovereignty
capability-first authority
no ambient root
small mechanism-focused kernel
typed/routed contracts
Job/resource hierarchy
immutable program/system generations
explicit durable state
health-gated lifecycle
Known-Good rollback
trusted control boundary
local/offline-first operation
structured observability
native software not paying for optional subsystems
```

Concrete implementations should remain replaceable.

Possible future replacements include:

```text
scheduler
memory policy
filesystem
storage allocator
compositor
desktop shell
network stack internals
audio engine
drivers
services
AI provider
compatibility runtime
ISA translator
extension runner
build backend
```

---

# E-026.2 — Architecture Is Not the Current Source Tree

Current:

```text
crate names
directory names
helper functions
struct layouts
private classes
```

are not architectural promises unless deliberately promoted to stable contracts.

Evrosion's identity lives in behavior and contracts, not current implementation layout.

---

# E-026.3 — Architectural Invariants

The long-term architecture should preserve these invariants:

```text
No authority without explicit capability/trusted mechanism
No automatic process-wide root
Owner remains final authority
Kernel remains mechanism-focused
Policy remains replaceable where practical
System services remain supervised
Failures remain containable
State and code remain separable
Updates remain transactional and rollback-aware
Stable contracts remain versioned/tested
Optional systems never become mandatory roots
User data is not destroyed to repair the OS
```

---

# E-026.4 — Separate Version Identities

Evrosion must not overload one OS version number with unrelated meanings.

Use separate identities for:

```text
Evrosion Release
System Generation
Platform API Level
Contract major/minor
ABI fingerprint
Package/component version
Build ID
State schema epoch
Compatibility cohort identity
```

Do not infer one from another.

---

# E-026.5 — Release Version

A release identifies a concrete implementation set.

It answers:

> Which implementation bundle shipped?

It does not define every developer-facing contract by itself.

---

# E-026.6 — System Generation

A System Generation identifies an immutable bootable system state under E-012/E-019.

Generation identity is local lifecycle state.

---

# E-026.7 — Platform API Level

The human-readable Platform API Level identifies the stable developer-facing Evrosion surface.

Applications/extensions target this level.

---

# E-026.8 — Contract Versions

Each E-015 contract has its own:

```text
major
minor
availability
```

information.

A Platform API Level represents a coherent set of contract versions.

---

# E-026.9 — ABI Fingerprints

Generated ABI fingerprints are machine-oriented compatibility evidence.

They are not the primary human versioning model.

---

# E-026.10 — State Schema Epochs

Persisted state must identify its format independently of code version.

Code v5 does not imply state schema v5.

---

# E-026.11 — Platform API Lifecycle

A useful lifecycle is:

```text
Development
 ↓
Preview / NEXT
 ↓
Supported
 ↓
Sunset
 ↓
Retired
```

Exact product terminology may evolve.

The semantics should not.

---

# E-026.12 — Development / Preview

Development interfaces may change rapidly.

Preview interfaces are intended for early adoption/testing but still carry limited guarantees.

They must be clearly marked.

---

# E-026.13 — Supported API Level

A Supported Platform API Level carries the ordinary compatibility guarantee.

Software targeting that level should continue to work on releases that claim support for it.

---

# E-026.14 — Sunset API Level

Existing software may continue running.

The SDK may stop encouraging/building new software for that level.

Sunset creates migration time without keeping history in the core forever.

---

# E-026.15 — Retired API Level

Retired historical support may move into:

```text
Compatibility Capsules
Compatibility Realms
adapters
legacy runtimes
VMs
```

where justified.

---

# E-026.16 — History Moves Outward

Core rule:

> **Historical compatibility burden moves outward instead of accumulating forever in the privileged/current core.**

The current native platform stays current and understandable.

---

# E-026.17 — Retirement Never Means Data Destruction

Retiring an API or runtime does not mean:

```text
delete application
delete user data
disable device
```

Compatibility migration/retention is handled explicitly.

---

# E-026.18 — Stable Means Tested

A stable compatibility promise is incomplete without automated proof.

Every supported Platform API Level should have frozen compatibility fixtures.

---

# E-026.19 — Frozen Compatibility Artifacts

Preserve representative pre-built:

```text
clients
servers
packages
protocol fixtures
ABI fixtures
```

from supported levels.

Run them continuously against current platform builds.

---

# E-026.20 — Old Client Against New Platform

CI should catch:

```text
API breakage
ABI breakage
behavior change
protocol incompatibility
lifetime mismatch
error-semantics change
```

before release.

---

# E-026.21 — Behavioral Compatibility

Matching symbols is not enough.

Stable semantics may include:

```text
error behavior
ordering
cancellation
lifetime
capability behavior
failure behavior
resource rules
```

where specified by the contract.

---

# E-026.22 — Side-by-Side Replacement

Major subsystem replacement should normally follow:

```text
Implementation A active
        ↓
Install B beside A
        ↓
Validate B
        ↓
Migrate/clone required state
        ↓
Conformance/differential tests
        ↓
Activate bounded cohort
        ↓
Health probation
        ↓
Commit
        ↓
Retire A later
```

---

# E-026.23 — Prefer Replacement Over Permanent Layering

Do not leave:

```text
old implementation
under new implementation
under newer implementation
```

forever.

Use migration, commit and retirement.

Otherwise the system becomes geological sediment.

---

# E-026.24 — Shadow Validation

Where safe and non-committing, a new provider may receive mirrored inputs and compare results with the active provider.

Never duplicate external side effects blindly.

Do not accidentally:

```text
send twice
charge twice
write twice
flash firmware twice
```

---

# E-026.25 — Health-Gated Commit

A replacement becomes authoritative only after required health gates pass.

E-019 remains authoritative.

---

# E-026.26 — Commit Horizon

Rollback state remains retained until the commit horizon ends.

Only then may irreversible cleanup/finalization happen.

---

# E-026.27 — Irreversible Migration Comes Last

Do not irreversibly rewrite state before rollback is no longer promised unless no reversible design exists.

---

# E-026.28 — Durable State Outlives Implementations

Every persistent service/system state should have:

```text
schema identity
epoch/version
validation
migration rules
```

The implementation may change while state remains valid.

---

# E-026.29 — State Migration Is Transactional

A migration should follow:

```text
validate old state
snapshot/checkpoint
migrate
validate new state
activate new implementation
probation
commit
```

---

# E-026.30 — Rollback-Compatible State Window

Techniques may include:

```text
additive schema
dual-read
copy-on-write state
side-by-side state
snapshot
reverse migration
```

as appropriate.

---

# E-026.31 — User Data Is Different

System generation rollback must not casually roll back user-created content.

System state and user content have different lifecycle semantics.

---

# E-026.32 — Rebuildable Derived State

Caches, indexes and registries should remain reconstructable where practical.

Do not accidentally turn caches into irreplaceable truth.

---

# E-026.33 — Durable Truth Is Minimal

Prefer:

```text
immutable packages
immutable generations
small durable bindings/config
rebuildable indexes
explicit user data
```

The less irreplaceable mutable state exists, the easier recovery becomes.

---

# E-026.34 — Cryptographic Agility

Evrosion must not hard-code one cryptographic algorithm forever.

Signed/encrypted artifacts should identify:

```text
algorithm
parameters/version
key identity
```

where relevant.

---

# E-026.35 — Algorithm Migration

A cryptographic transition may use:

```text
old accepted
+
new introduced
↓
dual-trust transition
↓
new required
↓
old retired
```

according to the threat model.

---

# E-026.36 — Signature Never Equals Authority

Even after decades:

> Provenance answers who produced it. Capabilities answer what it may do.

---

# E-026.37 — Complexity Budgets

Evrosion should explicitly treat several types of complexity as architectural resources.

No fixed number is required initially.

Growth must be justified.

---

# E-026.38 — Kernel / TCB Budget

New privileged code must answer:

```text
Why must this be privileged?
Why can't existing mechanisms express it?
What authority does it gain?
What happens if it fails?
How is it tested/audited?
```

---

# E-026.39 — Boot-Critical Budget

Every component required before recovery-capable boot increases systemic fragility.

Boot roots should stay small.

---

# E-026.40 — Always-On Service Budget

A permanent daemon costs:

```text
memory
wakeups
attack surface
lifecycle complexity
debug complexity
```

Demand activation should be preferred where appropriate.

---

# E-026.41 — Stable API Budget

Every Stable contract is a compatibility promise.

Stabilization must remain deliberate.

---

# E-026.42 — Mechanism Budget

Before adding another system-wide mechanism, first ask whether an existing mechanism can express the need.

Avoid accidental:

```text
second permission system
second updater
second package model
second Job hierarchy
second diagnostics framework
second trusted-control path
second lifecycle engine
```

---

# E-026.43 — Simplification Target

Long-term architecture should continue converging around:

```text
one capability model
one Job/resource model
one protocol/IDL system
one deployment/lifecycle engine
one trusted control environment
one federated observability model
one package/content model
```

---

# E-026.44 — No Shadow Architecture

A subsystem must not invent a private parallel framework simply because the shared architecture is inconvenient.

If shared mechanisms are insufficient:

improve them deliberately.

---

# E-026.45 — Architecture Index

Maintain one authoritative:

> **Architecture Index**

covering:

```text
F-001 ... F-014
Universal Rules
E-001 ... E-026
Stable contracts
Current implementations
Maturity/status
Tests
Known exceptions
Migration plans
```

---

# E-026.46 — Architecture Decision Records

Major architecture changes should have ADRs containing:

```text
problem
decision
alternatives
affected invariants
compatibility impact
migration
rollback
tests
```

---

# E-026.47 — Architecture Exceptions

Temporary violations during bringup/migration must record:

```text
what is violated
why
scope
owner/component
removal condition
affected tests
```

Temporary shortcuts may not silently become stable APIs.

---

# E-026.48 — Architecture Fitness Suite

Maintain automated tests that verify architectural promises across the complete system.

This is broader than unit testing.

---

# E-026.49 — Capability Fitness

Examples:

```text
no capability → denied
attenuation cannot regain rights
revocation removes grant
foreign root != Evrosion authority
```

---

# E-026.50 — Failure Containment Fitness

Deliberately crash:

```text
app
service
driver host
extension
policy service
```

and verify unrelated components continue.

---

# E-026.51 — Update / Recovery Fitness

Repeatedly test:

```text
valid update
invalid generation
interrupted activation
failed health check
reboot during update
Known-Good rollback
```

---

# E-026.52 — Durable Operation Fitness

Power-cut tests verify that operations end in:

```text
old committed state
or
new committed state
```

never arbitrary half-state.

---

# E-026.53 — Compatibility Fitness

Frozen old binaries and contracts run against current supported platform levels.

---

# E-026.54 — State Migration Fitness

Test:

```text
forward migration
new-code operation
rollback before commit horizon
corruption handling
old-readable state where promised
```

---

# E-026.55 — Provider Replacement Fitness

E-024 providers should be replaceable without consumers depending on implementation identity unless explicitly declared.

---

# E-026.56 — Extension Fitness

Inject:

```text
crash
hang
OOM
timeout
malformed response
quarantine
fallback
```

and verify host correctness.

---

# E-026.57 — Compatibility Reference Fitness

E-022 supported foreign contracts should continue differential testing against reference systems.

---

# E-026.58 — AI Fitness

When E-021 is implemented, test:

```text
prompt injection
quarantined content
malicious tool output
authority escalation
secret exfiltration
child-agent escalation
```

and verify deterministic containment.

---

# E-026.59 — Resource Fitness

Stress CPU/memory/GPU/storage and verify:

```text
critical responsiveness
background yielding
pressure recovery
OOM behavior
deadline behavior where admitted
```

---

# E-026.60 — Recovery Independence Fitness

Recovery must still work when normal optional services are unavailable.

---

# E-026.61 — Reproducible Build Fitness

Official canonical unsigned artifacts should remain reproducible under E-014 policy.

---

# E-026.62 — Performance Fitness

CI should track:

```text
boot latency
IPC latency
app launch
frame tail latency
memory footprint
storage latency
energy where measurable
```

---

# E-026.63 — Architecture Claims Become Tests

Core rule:

> **If an architectural promise can be tested automatically, eventually make it a test.**

---

# E-026.64 — QEMU Remains Permanent

QEMU remains a permanent:

```text
reference target
CI target
fault-injection environment
recovery test environment
architecture regression target
```

even after real hardware support matures.

---

# E-026.65 — Hardware Expansion

A sensible long-term expansion is:

```text
QEMU
↓
one x86-64 reference machine
↓
small x86 reference set
↓
broader x86 PCs
↓
ARM64 reference hardware
↓
future RISC-V where useful
```

Exact order may change.

---

# E-026.66 — No Vendor Defines Public Architecture

Supporting one GPU/NIC/CPU vendor must not turn vendor-specific assumptions into Evrosion's public contract.

---

# E-026.67 — Hardware Capability Discovery

Software should reason from:

```text
available capabilities
performance features
security features
power features
```

rather than hard-coded brand assumptions.

---

# E-026.68 — Graceful Hardware Degradation

Missing:

```text
IOMMU
TPM
advanced GPU
hardware codec
accelerator
```

should produce defined degraded behavior where possible.

---

# E-026.69 — New CPU Architectures

A new ISA port implements generic low-level contracts:

```text
boot
memory mapping
interrupts/timers
context switch
atomic primitives
architecture layer
```

It should not fork higher-level policy.

---

# E-026.70 — No Architecture Fork

Avoid separate:

```text
Evrosion-x86 policy
Evrosion-ARM policy
```

Hardware-specific mechanism lives beneath shared architecture.

---

# E-026.71 — 32-Bit Remains Compatibility-Only

Legacy 32-bit application support does not require a native 32-bit Evrosion architecture.

---

# E-026.72 — Hardware Support Lifecycle

Hardware support may use states such as:

```text
Reference
Supported
Maintenance
Community / Retired
```

Exact names may evolve.

---

# E-026.73 — Hardware End of Support

When official support ends:

```text
state it clearly
preserve owner access
preserve boot where technically possible
allow community/custom maintenance
avoid intentional lockout
```

---

# E-026.74 — End of Support Never Intentionally Bricks

Evrosion may stop promising fixes.

It must not intentionally disable the machine merely because support ended.

---

# E-026.75 — Self-Hosting Is a Maturity Goal

Evrosion should eventually be able to perform substantial Evrosion development from within itself.

This is dogfooding, not purity.

---

# E-026.76 — Keep Cross-Build Paths

Even after self-hosting, preserve external:

```text
CI builds
recovery builds
cross-builds
```

A broken Evrosion should not be the only environment capable of repairing Evrosion.

---

# E-026.77 — Evrosion Development Kit

Eventually publish a generated SDK/Development Kit from stable contracts.

Third parties should not require private source-tree internals.

---

# E-026.78 — Developers Target Contracts

External software targets:

```text
Platform API Level
contract versions
declared capabilities
package format
```

not exact internal compiler/library layouts.

---

# E-026.79 — Compiler-Private ABI Is Not Public ABI

E-013/E-015 remain authoritative.

Public boundaries avoid unstable language/compiler-native ABI where long-term compatibility is required.

---

# E-026.80 — Native Ecosystem Remains Primary

Compatibility lowers adoption cost.

Native Evrosion remains the intended long-term platform target.

---

# E-026.81 — Compatibility Is Bridge Infrastructure

Foreign compatibility exists to:

```text
preserve software
ease migration
reduce adoption friction
```

not to define Evrosion's native design.

---

# E-026.82 — Compatibility Evolves Independently

Windows/Linux/macOS/Android personalities and translators have independent versions/lifecycle.

They should not force whole-system releases when stable contracts permit independent updates.

---

# E-026.83 — Native Software Pays No Permanent Compatibility Cost

Unused compatibility components remain inactive or uninstallable where possible.

---

# E-026.84 — Extensions Stay Contract-Bound

Popularity of an extension ecosystem must not pressure Evrosion into:

```text
global hooks
ambient host privilege
arbitrary kernel modules
unversioned plugin ABI
```

E-024 remains authoritative.

---

# E-026.85 — AI Remains Optional Forever Architecturally

AI may become deeply integrated and useful.

It must never become required for:

```text
boot
file access
settings
updates
recovery
ownership
security approval
```

---

# E-026.86 — AI Providers Remain Replaceable

No specific cloud/local model becomes architectural infrastructure.

---

# E-026.87 — AI Never Becomes Authority Root

Future intelligence does not change:

> **The model proposes. Deterministic Evrosion authority executes.**

---

# E-026.88 — Cloud Is Never an Ownership Dependency

If:

```text
AI provider disappears
store disappears
Evrosion servers disappear
sync provider disappears
```

the owner should still be able to:

```text
boot
access local files
install local packages
change settings
recover
administer locally
```

---

# E-026.89 — No Forced Account Architecture

Core ownership/local use does not require an online account.

---

# E-026.90 — No Mandatory Telemetry

System operation does not depend on telemetry collection.

Diagnostics remain local-first.

---

# E-026.91 — No Advertising Dependency

Core operating-system functionality never depends on advertising infrastructure.

---

# E-026.92 — Release Channels

Evrosion may offer:

```text
Stable
Preview/Beta
Developer
```

or equivalent channels.

They all use the same E-019 lifecycle engine.

---

# E-026.93 — Security Updates Remain Free

Essential security fixes remain free for installations inside their declared support lifetime.

---

# E-026.94 — Declared Support Lifetime

Evrosion should explicitly state:

```text
what is supported
for how long / under what policy
what support means
```

Do not imply infinite maintenance promises the project cannot honor.

---

# E-026.95 — End of Support Is Not Forced Shutdown

Unsupported systems may lose official fixes.

They keep local ownership and operation subject to hardware/software reality.

---

# E-026.96 — Recovery Remains Independent

Recovery must resist dependencies on:

```text
marketplace
cloud account
AI
normal shell
network
```

unless those are optional supplemental paths.

---

# E-026.97 — Known Good Remains Protected

Do not delete the only known-good recovery path merely to reclaim ordinary space.

---

# E-026.98 — Maturity Is Gate-Based

Evrosion should not promise architectural maturity by calendar date.

Versions advance when exit criteria are satisfied.

---

# E-026.99 — Era A: Bringup

E-025 / 0.1 proves:

```text
QEMU
kernel spine
capability userspace
persistent generations
graphical shell
native app
rollback
```

---

# E-026.100 — Era B: Connected Developer Alpha

Adds:

```text
networking
first real hardware
remote tooling
richer diagnostics
initial hardware/media work
```

---

# E-026.101 — Era C: Native Developer Platform

Primary goal:

> Third-party developers can build serious native Evrosion software against an intentional SDK.

Likely requirements:

```text
stable initial Platform API Level
SDK/tooling
network
richer storage/files
media baseline
accelerated graphics path
package lifecycle
documentation
reference hardware
```

---

# E-026.102 — Era D: Ecosystem Alpha/Beta

Focus broadens toward:

```text
native app ecosystem
broader hardware
compatibility
extensions
accessibility
security UX
consumer polish
AI integration
```

---

# E-026.103 — Consumer 1.0 Is a Quality Gate

Do not call 1.0 because the number looks nice.

Likely criteria include:

```text
reliable boot/recovery
safe update lifecycle
stable API support policy
coherent desktop/file/settings UX
networking
basic media
reference hardware
security/ownership UX
accessibility baseline
diagnostics
reasonable performance/power
native SDK
package lifecycle
```

Exact product criteria may evolve.

---

# E-026.104 — Compatibility Does Not Define 1.0

Running foreign applications may be essential for adoption.

But the native platform must stand on its own.

---

# E-026.105 — AI Does Not Define 1.0

AI may improve usability greatly.

Deterministic local system control remains sufficient without it.

---

# E-026.106 — Vertical-Slice Planning

After bringup, development should be organized around complete outcomes such as:

```text
networked workstation
media workstation
gaming compatibility
developer workstation
accessible desktop
AI-assisted support
```

rather than blindly implementing architecture documents in numerical order.

---

# E-026.107 — Architecture Review Before Major Expansion

Before a major feature area lands, ask:

```text
Does an existing contract already cover it?
Does this expand the TCB?
Does this create a duplicate mechanism?
Does this add Stable API?
Can failure be contained?
Can it be rolled back?
Can it work offline where necessary?
```

---

# E-026.108 — Architectural Deletion Is Healthy

A mature Evrosion should actively remove:

```text
prototype backends
temporary adapters
duplicate mechanisms
obsolete implementations
dead workarounds
```

when stable promises allow it.

---

# E-026.109 — Delete Implementations, Respect Contracts

Replacing/removing an implementation is ordinary evolution.

Removing Stable contracts requires explicit deprecation/compatibility lifecycle.

---

# E-026.110 — Dependency Direction

Optional high-level features may depend on foundational systems.

Foundational systems must not depend on optional high-level features.

Example:

```text
AI may depend on storage
```

but:

```text
storage must not depend on AI
```

---

# E-026.111 — Optional Features Never Become Hidden Roots

These must not become required boot/recovery/security roots merely through popularity:

```text
AI
marketplace
cloud sync
compatibility
extension discovery
analytics
```

---

# E-026.112 — Trusted Computing Base Manifest

A mature release should be able to enumerate its effective TCB.

Possible entries:

```text
kernel
bootstrap
Trusted Control
boot verifier
critical security services
recovery components
critical capability brokers
```

with build/version identities where practical.

---

# E-026.113 — TCB Growth Is Reviewable

A release that expands the TCB should make that visible in architecture review.

---

# E-026.114 — Inspectable Boot Graph

Developers/owners should eventually be able to inspect:

```text
what must succeed for boot
what is optional
what fallback exists
what belongs to recovery
```

---

# E-026.115 — Inspectable Contract Graph

The system should be able to answer:

```text
who provides contract X
who consumes it
which version
which Provider Binding
which adapter
```

---

# E-026.116 — Inspectable Lifecycle

The owner/developer should see:

```text
active generation
Known Good
pending generation
commit horizon
rollback state
retained cohorts
```

---

# E-026.117 — Explainability Survives Maturity

Even a mature Evrosion should let an expert answer:

> Why did this happen?

without reverse engineering hidden global state.

---

# E-026.118 — Human-Readable, Machine-Readable

F-013 remains permanent.

Configuration/diagnostics should be understandable by people and structured for tooling.

---

# E-026.119 — Avoid Configuration Archaeology

Do not require knowledge of decades of undocumented config files to understand system behavior.

State/config schemas are explicit and versioned.

---

# E-026.120 — Migration Tooling Is First-Class

When stable formats/contracts change, migration tooling is part of the design.

Migration is not cleanup work after the real feature is done.

---

# E-026.121 — User Data Outlives the OS Implementation

System repair/replacement may replace:

```text
kernel
services
drivers
runtime
system generation
```

without requiring user-data destruction.

---

# E-026.122 — Exportability

For Evrosion-specific user formats, provide documented export/conversion paths where practical.

Ownership includes the ability to leave.

---

# E-026.123 — Ecosystem Lock-In Is Not Architecture

Users/developers should remain because Evrosion is good.

Not because their data/software cannot escape.

---

# E-026.124 — Marketplace Remains Replaceable

The official store can become important.

It remains one distribution path over the same package/lifecycle system.

---

# E-026.125 — Commercial Services Stay Above the Core

Enterprise support, hosted AI, certifications, paid preview channels and commercial licensing may evolve without redefining machine ownership.

---

# E-026.126 — Business Model Cannot Rewrite Security

Future commercial pressure must not require:

```text
forced cloud account
paid essential security fix
mandatory telemetry
locked boot
mandatory store
```

to make the project viable.

---

# E-026.127 — Community and Proprietary Components Can Coexist

Open core and proprietary third-party/commercial components may integrate through stable contracts according to licensing rules.

Architecture does not require one source license for all software.

---

# E-026.128 — Long-Term Documentation

Stable contracts require:

```text
reference docs
examples
compatibility guarantees
deprecation state
security model
failure model
```

Documentation is part of the platform.

---

# E-026.129 — Long-Term Test Artifacts Are Architectural Memory

Retain/version:

```text
compatibility fixtures
reference VM images
conformance suites
fault scenarios
build manifests
```

These preserve knowledge across years.

---

# E-026.130 — Historical Build Reproducibility

Important older releases should be reconstructable using archived/pinned toolchains where practical.

The current compiler does not need to build every historical source tree forever.

---

# E-026.131 — Runtime Compatibility Over Eternal Source Compatibility

Preserve supported platform contracts.

Do not freeze all internal historical source assumptions.

---

# E-026.132 — Security Evolution Can Reject Unsafe History

Compatibility does not require preserving an unsafe behavior that violates current security boundaries.

Unsafe historical semantics may require containment or may become unsupported.

---

# E-026.133 — Undocumented Privilege Is Not a Contract

A historical bug that leaked privilege is not a compatibility promise.

---

# E-026.134 — Performance Evolution

Implementations may change radically for performance while preserving stable semantics.

Fast paths remain semantically equivalent.

---

# E-026.135 — Performance Regression Is Architecture Risk

Growing abstraction layers can slowly destroy responsiveness.

Fitness testing should therefore include tail-latency/resource budgets.

---

# E-026.136 — Co-Location Remains Evidence-Based

Adaptive isolation may co-locate trusted components when measured benefit justifies it.

Do not fuse trust domains because same-process feels fashionable.

---

# E-026.137 — De-Co-Location Remains Possible

A co-located implementation should be able to move back into isolation without changing its stable logical contract.

---

# E-026.138 — Recovery Stays Small

As normal Evrosion grows, recovery should not grow at the same rate.

Recovery needs enough to:

```text
boot
inspect
select Known Good
repair essentials
restore system generation
preserve user data
```

---

# E-026.139 — Recovery Is Not a Second Full OS

Duplicating every normal feature into recovery doubles maintenance and attack surface.

Keep recovery intentionally focused.

---

# E-026.140 — Build / Release Provenance

Official releases should be traceable to:

```text
source revisions
toolchain
build configuration
package identities
system generation
signing role
SBOM/provenance
```

---

# E-026.141 — Rollback Is Part of Release Design

A release is incomplete until its failure/recovery path is known.

---

# E-026.142 — Continuous Architecture Audit

Major subsystem work should be periodically checked against E-026.

Questions include:

```text
Did we introduce duplicate mechanisms?
Did TCB grow?
Did boot-critical surface grow?
Did Stable API grow?
Did old compatibility move into core?
Did optional service become mandatory?
Can owner still operate offline?
Can system still roll back?
Can failure still be localized?
Can current state still be explained?
```

---

# E-026.143 — Successful Growth May Simplify

A mature subsystem should be allowed to remove prototype scaffolding and old transitional layers.

Growth is not always addition.

---

# E-026.144 — No Feature Is Sacred

A feature can be replaced/removed if:

```text
Stable promises are honored
user data is preserved
migration exists where promised
owner control remains intact
```

---

# E-026.145 — Core Principles Are Constitutional

Changing a feature is ordinary evolution.

Changing:

```text
owner sovereignty
capability authority
rollback guarantees
privacy model
local-first ownership
```

is a constitutional architecture change.

The burden of proof belongs to the proposed change.

---

# E-026.146 — Convenience Is Not Enough

"We can ship faster" does not by itself justify breaking foundational ownership/security design.

---

# E-026.147 — Owner Sovereignty Survives Maturity

Commercial success, enterprise use, AI integration, ecosystem growth or cloud features never remove the owner's Layer 3 authority over their machine.

---

# E-026.148 — Safe Defaults Do Not Become Forced Limits

Layers 1 and 2 may become smarter and safer.

Layer 3 remains deliberate owner control.

---

# E-026.149 — Offline Ownership Survives

A permanently disconnected device should retain, subject to installed software:

```text
boot
local apps
files
settings
recovery
local package installation
local administration
```

---

# E-026.150 — Time-Limited Online Trust Fails Safely

Stale online update metadata may block a new update.

It should not make already-installed trusted local software stop functioning merely because the network disappeared.

---

# E-026.151 — Vendor Disappearance Scenario

Architecture should tolerate:

```text
AI vendor disappears
store unavailable
Evrosion company unavailable
update server unavailable
```

without immediate loss of local ownership.

---

# E-026.152 — Project Continuity

Open core, reproducible builds, documented contracts, owner boot keys and sideloading improve the chance that Evrosion remains maintainable beyond any one company/team.

---

# E-026.153 — Future AGI Does Not Change Authority Law

Even dramatically more capable future AI does not automatically own the machine.

E-021 remains authority architecture, not intelligence-dependent policy.

---

# E-026.154 — Long-Term Formula

```text
Stable Invariants
      +
Stable Versioned Contracts
      +
Replaceable Implementations
      +
Transactional Migration
      +
Compatibility Windows
      +
Architecture Fitness Tests
      +
Complexity Budgets
      =
Long-Lived Evrosion
```

---

# E-026 Final Architecture Map

```text
FOUNDATIONS / UNIVERSAL RULES
            │
            ↓
   ARCHITECTURAL INVARIANTS
            │
            ↓
     STABLE CONTRACT LAYER
  Platform API Levels / IDL
            │
            ↓
 ┌──────────┼───────────┐
 │          │           │
Kernel    Services     Apps
Impl.      Impl.        Impl.
 │          │           │
 └──────────┼───────────┘
            │
     Replaceable over time
            │
            ↓
       E-019 Lifecycle
     stage / health / commit
            │
            ↓
      Known-Good Rollback
```

Compatibility history:

```text
Current Native Core
       │
       ├── Supported API Levels
       │
       └── Older History
              ↓
        adapters / capsules
        compatibility realms
        VMs where necessary
```

Governance:

```text
Architecture Index
       │
       ├── ADRs
       ├── Complexity Budgets
       ├── Exception Register
       └── Architecture Fitness Suite
```

---

# E-026 Final Summary

**Long-term model:** Evolutionary Platform Architecture

**Primary rule:** Stable laws, replaceable implementations

**Contract rule:** Freeze contracts, not internals

**Version model:** Separate release/generation/API/contract/ABI/package/schema identities

**API lifecycle:** Development / Preview / Supported / Sunset / Retired

**Historical compatibility:** Moves outward

**Stable compatibility:** Frozen-artifact regression tested

**Major replacement:** Side-by-side preferred

**Migration:** Transactional

**Irreversible migration:** After commit horizon

**User data:** Independent of system rollback

**Persistent state:** Explicit schema epochs

**Crypto:** Algorithm-agile

**TCB growth:** Budgeted/reviewed

**Boot-critical growth:** Budgeted

**Always-on services:** Budgeted

**Stable API growth:** Budgeted

**Duplicate mechanisms:** Strongly resisted

**Architecture source of truth:** Architecture Index

**Major decisions:** ADRs

**Temporary violations:** Explicit exceptions

**Architecture promises:** Fitness-tested

**QEMU:** Permanent reference/CI/fault platform

**Hardware expansion:** Gradual

**New ISAs:** Shared policy, arch-specific mechanisms

**32-bit:** Compatibility only

**Hardware EOS:** Never intentional bricking

**Self-hosting:** Maturity goal, not purity requirement

**Cross-build support:** Permanent

**SDK:** Generated from stable contracts

**Compatibility:** Optional bridge

**AI:** Optional forever architecturally

**Cloud:** Never ownership root

**Forced account:** No

**Mandatory telemetry:** No

**Advertising dependency:** No

**Security updates:** Free through declared support lifetime

**Recovery:** Independent and intentionally small

**Known Good:** Protected

**Maturity:** Gate-based

**Architecture deletion:** Healthy

**Owner authority:** Constitutional invariant

---

# Governing Principles

> **Freeze the laws that make Evrosion Evrosion. Keep implementations replaceable.**

> **Freeze contracts, not internals.**

> **Version everything that persists or crosses a stable boundary.**

> **Never overload one version number with unrelated meanings.**

> **Stable means compatibility-tested.**

> **A compatibility promise without frozen regression tests is incomplete.**

> **Major implementations evolve through side-by-side replacement, health-gated activation, and rollback where practical.**

> **Irreversible state migration happens only after the rollback commitment ends.**

> **User data should outlive system implementations.**

> **Historical compatibility moves outward instead of accumulating forever in the core.**

> **The native platform is not frozen by foreign operating-system history.**

> **Privileged code, boot-critical code, always-on services, and Stable APIs all consume architecture budget.**

> **Before inventing a second global mechanism, prove why the first cannot solve the problem.**

> **One capability model. One Job/resource model. One protocol system. One lifecycle engine. One trusted control environment. One federated observability model. One package/content model.**

> **No shadow architectures.**

> **Architecture exceptions are explicit, scoped, temporary, and removable.**

> **Architecture claims become executable tests wherever possible.**

> **QEMU remains a permanent reference platform even after real hardware support matures.**

> **Hardware vendors never define Evrosion's public architecture.**

> **Self-hosting improves Evrosion but never eliminates external build/recovery paths.**

> **Compatibility remains bridge infrastructure. Native Evrosion remains the destination.**

> **AI remains optional and never becomes the authority root.**

> **Cloud services may disappear without taking ownership of the computer with them.**

> **Security updates remain free throughout the declared support lifetime.**

> **End of support never intentionally bricks the machine.**

> **Recovery stays smaller than the normal operating system.**

> **Delete obsolete architecture instead of preserving endless geological layers.**

> **Performance optimizations may change implementation without erasing stable semantics or security boundaries.**

> **Safe defaults may become smarter. Owner sovereignty does not become weaker.**

> **Offline ownership survives maturity, commercialization, compatibility, AI, and cloud integration.**

> **The owner remains the final authority.**

**E-026 — DECIDED AND CLOSED.**

---

# External Design References Consulted During Final Pass

The final pass used these as design references rather than dependencies:

- Fuchsia Platform Versioning — explicit API levels, support phases, and separation of platform interfaces from release implementation.
- Fuchsia Compatibility Test Framework — freezing previous-release artifacts and running them against the current platform to detect compatibility regressions.
- seL4 release/versioning model — explicit releases, pinned manifests and minimal privileged kernel philosophy.
- ChromeOS A/B update architecture — retaining a previous bootable system and rolling back when a new system fails boot/health criteria.

Evrosion retains its own capability model, ownership model, lifecycle architecture, compatibility design and recovery system.
