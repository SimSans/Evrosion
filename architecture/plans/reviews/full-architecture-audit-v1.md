# Evrosion — Full Architecture Audit v1

**Audit scope:** Foundations F-001–F-014, Universal Rules U-000–U-018, E-001 through E-026  
**Status of architecture being audited:** Core architecture sequence complete  
**Audit purpose:** Check coherence, contradictions, duplicated mechanisms, hidden roots of failure/authority, missing cross-cutting concerns, overengineering risk, unresolved implementation choices, and readiness to begin E-025/M0 implementation.

---

# 1. Executive Verdict

The architecture is **coherent enough to begin implementation**.

There is no contradiction in E-001 through E-026 that requires Evrosion to be redesigned from scratch.

The strongest result of the design process is not any individual subsystem. It is the fact that nearly every subsystem converges on the same small number of architectural laws:

```text
Authority
→ capabilities

Work / accounting
→ Jobs + Work Contexts

Communication
→ typed IPC + Memory Objects

Software identity / packaging
→ AppIdentity + immutable packages/content

Lifecycle
→ E-019 transactional activation / health / rollback

Recovery
→ Known-Good generations + independent Trusted Control

Observability
→ structured state/events/traces + Failure Capsules

Extensibility
→ typed contracts + Provider Bindings

Compatibility
→ personalities/realms outside the native core

AI
→ proposals behind deterministic authority

Performance
→ resource-specific enforcement under one Job hierarchy
```

That coherence is the architecture's largest asset.

The design is also notably resistant to the most common way long-lived operating systems become unmanageable:

```text
new feature
→ new exception
→ new private mechanism
→ new compatibility hack
→ new privileged daemon
→ permanent architectural sediment
```

E-015, E-019, E-024 and E-026 collectively give Evrosion an explicit way to resist that failure mode.

The audit does, however, identify several pieces of **connective architecture that should be made explicit before the relevant implementation milestone**.

These are not reasons to reopen the 26 core decisions.

They are missing details at the boundaries between those decisions.

The most important are:

1. Root authority custody and reconstitution after Root Supervisor failure.
2. Durable permission/grant persistence across reboot.
3. System time / monotonic time / UTC / secure-time architecture.
4. Entropy and cryptographic random-number architecture.
5. Multi-user, login-session, owner, guest and remote-session semantics.
6. Suspend/resume/system power-state architecture.
7. Hypervisor / virtualization boundary for E-022 VM fallback.
8. Explicitly splitting E-021 AI authority into a logical control plane rather than one all-powerful process.
9. General TOCTOU-safe approval/action binding for privileged actions.
10. Storage-encryption key lifecycle and recovery.
11. Globalization/text/input-method/timezone architecture before consumer maturity.
12. Explicit IPC deadlock/reentrancy discipline before the service graph becomes large.

Everything else found by this audit is either:

```text
already solved
implementation detail
deliberately postponed
or
appropriate long-term optional work
```

---

# 2. Evrosion in One Architectural Sentence

Evrosion is a:

> **Capability-first, userspace-oriented, recoverable operating system whose privileged core exposes mechanisms rather than policy; whose services, applications, drivers, compatibility environments, AI agents and extensions operate through typed contracts and explicit capabilities; whose state and software lifecycle are transactional and rollback-aware; and whose owner retains deliberate final authority over the machine.**

---

# 3. Foundational Consistency Audit

## F-001 — Human–Computer Relationship

**Status: Consistent**

The architecture consistently prioritizes:

```text
simple default operation
progressive disclosure
explainability
recovery
user intent
```

without requiring the simple layer to become the only layer.

E-017, E-020, E-021, E-023 and the three-layer UX model strongly support this.

No contradiction found.

---

## F-002 — Absolute Ownership

**Status: Consistent, with one implementation warning**

Layer 3 remains the explicit owner-controlled escape from protective policy.

Important supporting decisions:

```text
owner-controlled boot choices
owner keys
custom kernel possible
unsigned software possible in deliberate Layer 3 paths
no mandatory store
no mandatory cloud
no forced online account
AI never owns authority
foreign root never equals Evrosion authority
```

The main implementation warning is that "owner authority" must not accidentally become synonymous with:

```text
one fragile mutable userspace Root Supervisor process
```

Root authority custody is addressed later in this audit.

---

## F-003 — Progressive Responsibility

**Status: Strongly consistent**

The same underlying mechanisms are preserved across Layers 1–3.

The layers alter:

```text
visibility
default policy
approval friction
allowed automatic actions
```

rather than creating three different operating systems.

This is correct.

The most important implementation rule is:

> Layer 3 must widen owner control without automatically widening every process's authority.

E-009 already establishes this.

---

## F-004 — Self-Configuring Hardware & System

**Status: Architecturally supported, intentionally incomplete in E-025**

E-003/E-006 provide the long-term structure.

E-025 correctly prevents broad hardware support from blocking 0.1.

No contradiction.

---

## F-005 — Compatibility Without Surrender

**Status: Strong**

E-022 is highly aligned with this foundation.

Foreign semantics are contained in:

```text
personalities
Compatibility Realms
ISA translators
VMs
```

rather than entering the native kernel/API architecture.

No major issue found.

---

## F-006 — Graceful Degradation

**Status: Strong**

Appears consistently in:

```text
no-IOMMU weaker security tier
software graphics fallback
audio/media fallback
network degradation
memory pressure ladder
resource pressure policy
AI fallback
compatibility fallback
recovery
```

No conflict.

---

## F-007 — Observable System

**Status: Exceptionally strong**

E-020 plus the inspection requirements in E-007/E-019/E-023/E-024/E-026 make observability a first-class architectural property.

Important principle preserved:

> No single global mutable diagnostics database becomes system truth.

No issue.

---

## F-008 — Accessibility Is Fundamental

**Status: Architecturally preserved; implementation maturity intentionally deferred**

E-017 establishes semantic accessibility parallel to pixels.

E-024 requires UI-extension semantics.

The remaining requirement is to ensure:

```text
Trusted Control
recovery
login/session UI
permission/authority approval UI
```

remain accessible as they are implemented.

This should become an architecture fitness test when those UIs exist.

---

## F-009 — Modular by Design

**Status: Strong**

E-007/E-015/E-024/E-026 reinforce each other.

The audit agrees with E-026's warning:

> Modularity must not become component-count maximization.

No contradiction.

---

## F-010 — No Unrecoverable Root of Failure

**Status: Mostly satisfied; one high-priority connective issue remains**

Strong existing protections:

```text
userspace services restart
drivers userspace by default
resource policy not fast-path root
provider resolver not fast-path root
AI optional
recovery independent
Known-Good generations
federated observability
```

Remaining issue:

> The Root Supervisor receives initial root capabilities, but the exact mechanism that safely recreates the Root Supervisor and restores initial authority after its catastrophic failure is not yet explicit.

This should be resolved before M2.

See Finding A-001.

---

## F-011 — Local First

**Status: Strong**

No cloud dependency is architectural.

Already-installed software remains usable offline.

Recovery remains local.

No issue.

---

## F-012 — Evolvability

**Status: Exceptional**

E-015/E-019/E-024/E-026 make this one of the best-developed foundations.

No redesign required.

---

## F-013 — Human-Readable by Default, Machine-Readable Underneath

**Status: Strong**

Structured diagnostics, IDL contracts, manifests, package metadata and inspectable lifecycle state fit this well.

No issue.

---

## F-014 — No Artificial Walls

**Status: Consistent**

The owner retains Layer 3 control.

Restrictions in Layers 1–2 are safety policy, not absolute ownership denial.

No contradiction.

---

# 4. Universal Rule Audit

The Universal Rules are mutually compatible.

Particularly strong combinations are:

```text
Simple by Default
+
Capability Preservation
+
Progressive Disclosure
```

and:

```text
Safe by Default
+
Never Paternalistic
+
User Ownership
```

and:

```text
Automation With Control
+
Explainable
+
Transparent State
```

and:

```text
Failure Is Expected
+
Reversible Where Possible
+
Observable System
```

No Universal Rule currently forces an architectural contradiction.

The rules that deserve the most implementation vigilance are:

```text
U-005 Never Paternalistic
U-013 Automation With Control
U-016 AI Is a Tool, Not the Authority
U-017 User Intent Over Implementation
```

because product/UI decisions can violate them even when the technical architecture does not.

---

# 5. Core Mechanism Consolidation Audit

A major question was whether the 26 chapters accidentally created duplicate global mechanisms.

The answer is:

> **Mostly no.**

The simplification target remains coherent.

## Authority

Primary mechanism:

```text
E-009 capabilities
```

Other systems correctly reuse it:

```text
drivers
services
apps
AI
extensions
compatibility
debugging
files
network
devices
```

**Audit result:** No second security model is required.

---

## Work / Resource Ownership

Primary mechanism:

```text
E-004 Job hierarchy
+
Scheduling Context / Work Context
+
E-023 Resource Contracts
```

AI Sessions and Compatibility Realms remain Jobs.

**Audit result:** Coherent.

---

## Communication

Primary mechanisms:

```text
typed IPC for control
Memory Objects / shared buffers for bulk
specialized rings for high-frequency async paths
```

E-008 correctly keeps semantics consistent across fast paths.

**Audit result:** Coherent.

---

## Lifecycle

Primary mechanism:

```text
E-019 Lifecycle Engine
+
E-010 Durable Operations
+
E-012 System Generations
```

Apps, services, drivers, extensions, codecs, compatibility runtimes and models reuse this.

**Audit result:** Excellent consolidation.

---

## Packaging

Primary mechanism:

```text
E-016 `.sion`
+
immutable content graph / CAS concepts
```

E-024 extensions reuse `.sion`.

Local AI models can reuse it.

**Audit result:** Coherent.

---

## Contracts / API

Primary mechanism:

```text
E-015 IDL / Platform API Level
```

Services, extension points, AI tools and compatibility adapters all reuse contracts.

**Audit result:** Strong.

---

## Observability

Primary model:

```text
STATE
EVENTS / LOGS
TRACES
+
Flight Recorders
+
Failure Capsules
```

No subsystem needs a second diagnostic universe.

**Audit result:** Strong.

---

## Trusted Control

Primary mechanism:

```text
Secure Attention
+
Trusted Control Plane
```

E-009/E-012/E-021 correctly rely on it.

**Audit result:** Good.

---

# 6. Cross-Document Coherence Audit

## E-001 + E-002

**Result: Coherent**

E-001's adaptive capability-oriented microkernel architecture is faithfully implemented by E-002's mechanism-only kernel.

No subsystem later requires abandoning the microkernel model.

Potential performance exceptions are already handled through:

```text
shared memory
direct-call adapters
adaptive co-location
```

rather than moving policy into the kernel.

---

## E-003 + E-006

**Result: Coherent**

Hardware capability tiers and driver isolation match.

No-IOMMU systems explicitly receive weaker isolation rather than pretending equivalence.

Good.

---

## E-004 + E-008 + E-023

**Result: Very strong**

These three form a coherent work-accounting system:

```text
Job
↓
Work Context
↓
IPC/dependency
↓
causal accounting / bounded urgency
```

This is one of Evrosion's strongest architectural combinations.

Implementation caution:

Do not make Work Context unbounded metadata that every hot path constantly copies.

Use compact IDs and local lookup/caching where necessary.

---

## E-005 + E-010

**Result: Coherent**

Memory Objects give storage/IPC/media/graphics a consistent shared-memory primitive.

Userspace paging and storage policies align.

Critical pager memory remains wired/emergency-reserved.

Good.

---

## E-007 + E-024

**Result: Excellent**

Service identity and Extension Point provider identity are compatible.

E-024 Provider Bindings decide **which provider**.

E-007 service routing decides **how clients reach it**.

These must remain separate.

---

## E-008 + E-015

**Result: Excellent**

IDL-generated protocols correctly sit above capability-aware IPC.

Direct-call or shared-memory optimization is implementation only.

Semantic equivalence remains mandatory.

---

## E-009 + E-016

**Result: Strong**

`.sion` capability declarations represent what applications may request.

They do not become grants.

Actual grants come from owner/policy/user-mediated capabilities.

Correct.

---

## E-010 + E-012 + E-019

**Result: Very strong**

These form a single durability/update architecture:

```text
durable storage operation
→ staged generation/component
→ activation
→ health
→ commit / rollback
```

This is one of the best-integrated areas of the design.

---

## E-011 + E-023

**Result: Coherent**

Networking exposes session/path semantics.

Resource policy provides Job-level QoS.

The OS correctly avoids pretending it can schedule the remote Internet.

---

## E-013 + E-015

**Result: Correct**

Rust is internal implementation language.

Public ABI does not depend on unstable Rust ABI.

C-compatible minimal boundary remains the lowest denominator.

---

## E-014 + E-020 + E-026

**Result: Excellent**

Reproducible builds, exact build IDs and compatibility fixtures create a strong debugging/evolution story.

No issue.

---

## E-016 + E-019 + E-024

**Result: Coherent**

Apps and extensions share:

```text
package
lifecycle
state separation
provider binding
```

without becoming the same concept.

Good.

---

## E-017 + E-018

**Result: Coherent**

Graphics and media share:

```text
Memory Objects
GPU Images
timestamps
Jobs
capabilities
```

without forcing one universal media execution engine.

Correct.

---

## E-021 + E-009

**Result: Conceptually correct, implementation amendment required**

E-021 correctly states:

```text
model output = proposal
capabilities = local deterministic authority
```

However, the final implementation must ensure the **AI Authority Broker is a logical security function, not one giant process holding universal owner/system capabilities**.

See Finding A-002.

---

## E-022 + E-009

**Result: Strong**

Foreign Administrator/root/SYSTEM remain compatibility-world identities.

They do not become Evrosion authority.

This is essential and correctly specified.

---

## E-022 + E-017/E-018/E-011/E-010

**Result: Strong**

Compatibility reaches native semantic subsystems at high-level boundaries.

This avoids emulating unnecessary lower layers.

No conflict.

---

## E-023 + E-004

**Result: Strong**

E-023 does not replace CPU scheduling.

It supplies Job/resource policy and pressure feedback.

Correct separation.

---

## E-024 + E-026

**Result: Strong**

Extension-point growth is explicitly budgeted.

Provider discovery/binding is reconstructable.

Good.

---

## E-025 + E-026

**Result: Excellent**

E-025 prevents future architecture from bloating 0.1.

E-026 prevents 0.1 implementation shortcuts from becoming permanent architecture.

These two chapters form a strong pair.

---

# 7. Hidden Centralization / "God Service" Audit

The architecture intentionally uses several logical control services.

They are safe only if none becomes a hidden root that all data/control must traverse.

## Root Supervisor

**Risk: HIGH if implemented naïvely**

It necessarily begins with initial root capability custody.

Required resolution:

- Kernel/bootstrap must have a deterministic way to recreate the designated initial supervisor after failure.
- Initial root authority must not exist only as unrecoverable mutable process state.
- Restart must not mint *additional* authority beyond the initial boot authority set.
- Recovery/Trusted Control must be able to enter a safe state if normal supervisor recreation repeatedly fails.

See A-001.

---

## Lifecycle Engine

**Risk: MEDIUM**

E-019 gives it major system-change authority.

Mitigations that must remain true:

```text
trust verification separate from network transport
signed metadata required where applicable
capabilities scoped
running system continues if lifecycle service crashes
current generation immutable
rollback state independent
```

The Lifecycle Engine must not become equivalent to unrestricted root.

---

## Resource Policy Service

**Risk: LOW**

E-023 already solves this well:

```text
not fast path
cached contracts
local enforcement
failure → conservative defaults
```

No further redesign.

---

## Provider Resolver

**Risk: LOW**

E-024 final pass correctly separates:

```text
catalog
binding
resolver
routed provider
```

Resolver is not authority source or data path.

Good.

---

## Observability

**Risk: LOW**

E-020 explicitly avoids one universal mutable state DB.

Correct.

---

## AI Authority Broker

**Risk: MEDIUM-HIGH unless amended**

Current conceptual model may be read as one trusted process owning all AI action capabilities.

That would violate the spirit of F-010.

Required implementation principle:

```text
AI Control Plane
├── Context Broker
├── deterministic authorization/policy function
├── Tool Invocation Brokers
├── Secret Broker / Vault interface
└── Model Router
```

The authorization component should operate only on authority delegated to the active AI Session.

It must not permanently own the entire machine.

Tool-specific invocation authority should be narrow.

Compromise of AI control components should be limited to current delegated session authority wherever technically possible.

See A-002.

---

# 8. Security / Authority Audit

Overall security model is strong.

The most important remaining details are not new permission systems.

They are about persistence, identity and atomicity.

---

# Finding A-001 — Root Authority Custody & Reconstitution

**Priority:** Must settle before M2  
**Severity:** High connective architecture issue  
**Does it invalidate existing design?** No

Current architecture says:

```text
Bootstrap Bundle
↓
Root Supervisor
↓
delegation
```

Missing explicit answer:

> What happens if Root Supervisor catastrophically dies after receiving the only authoritative root-capability set?

Recommended rule:

> **Initial root authority is a boot-defined authority set that can be deterministically reconstituted only for the designated Root Supervisor/recovery path, not an uncopyable secret accidentally trapped inside one process.**

Possible implementation shape:

```text
Kernel / Bootstrap Authority Object
        ↓
creates designated Root Supervisor
        ↓
issues initial bootstrap capability set
```

If the supervisor dies:

```text
bootstrap supervisor mechanism
or
minimal kernel-recognized restart path
```

may recreate the designated Root Supervisor and reissue the **same boot-defined authority**, not arbitrary new rights.

This mechanism must remain tiny and auditable.

Normal services still receive only delegated caps.

Layer 3 does not depend on a fragile single process to preserve ownership.

---

# Finding A-002 — AI Authority Broker Must Be Logical, Not Godlike

**Priority:** Before E-021 implementation  
**Severity:** High if ignored  
**Architecture change required:** Clarifying amendment only

Recommended invariant:

> **No single AI process permanently holds universal owner/system capabilities.**

Use:

```text
AI Session Grant Set
        ↓
deterministic authorization decision
        ↓
narrow invocation token/capability
        ↓
specific tool/service
```

The model cannot:

```text
mint
widen
renew
approve
```

its own authority.

Tool boundaries revalidate action authority.

Secrets remain in E-009 vault/broker.

AI Control Plane failure disables AI actions, not the OS.

---

# Finding A-003 — Durable Permission / Grant Persistence

**Priority:** Before M5 / real application permission UX  
**Severity:** Medium-High

E-009 defines runtime capabilities and revocable grants.

But the long-term model needs to distinguish:

```text
live capability
```

from:

```text
durable user policy saying a capability may be recreated later
```

A raw capability handle should not simply be serialized to disk.

Recommended model:

```text
Durable Grant Record
├── grant identity
├── subject identity
├── resource identity/scope
├── rights
├── constraints
├── origin / approver
├── revocation state
└── expiry / policy
```

At login/app activation:

```text
trusted grant service
↓
validates durable record
↓
mints fresh runtime capability
```

This should reuse E-010/E-019 durability.

AI Action Grants normally remain short-lived and session-local unless explicitly promoted.

Extension/provider bindings remain separate state types, but may reuse the same durable-state infrastructure.

Do not create multiple unrelated permission databases.

---

# Finding A-004 — TOCTOU-Safe Approval Binding

**Priority:** Before privileged UI/action automation becomes broad  
**Severity:** Medium

A user approving:

```text
delete /path/foo
```

must not accidentally approve a different object substituted before execution.

General rule:

> **Privileged approvals bind to canonical action identity and stable resource object identity where possible, then revalidate preconditions at execution.**

Prefer:

```text
File Object / object ID
generation/version
canonical action digest
preconditions
```

over mutable path strings alone.

This applies to:

```text
AI
install/update
file operations
credential actions
provider changes
destructive settings
```

---

# Finding A-005 — Unified Grant UX, Not Unified God Database

**Priority:** Before broad desktop/application UX  
**Severity:** Medium

Evrosion has several concepts:

```text
app permission grant
temporary file picker grant
AI action grant
debug grant
device grant
extension capability grant
```

They should share the **same capability/delegation semantics**.

They should not necessarily share one gigantic schema.

Recommended approach:

```text
common grant primitives
common revocation semantics
common trusted approval surface
domain-specific durable records
```

Avoid:

```text
five incompatible permission systems
```

but also avoid:

```text
one magical permission database knowing every subsystem
```

---

# 9. Missing Cross-Cutting Architecture Worth Adding as Annexes

These are the largest genuine gaps in the current 26-document set.

They do **not** justify reopening E-001–E-026.

They should be treated as focused cross-cutting annexes/design notes before the milestone that needs them.

---

# Annex Candidate X-001 — Time & Chronology Architecture

**Needed before:** serious networking, TLS, update freshness, user-facing calendar/time  
**0.1 blocker:** No  
**M6 blocker:** Likely yes

Evrosion already has:

```text
kernel timers
monotonic media clocks
deadlines
timestamps
```

but lacks one explicit whole-system time architecture.

Required concepts:

```text
monotonic clock
boot-time clock
wall/UTC clock
RTC
time synchronization
timezone / locale conversion
leap/clock-adjustment policy
secure/freshness-sensitive time
clock-change events
virtual/compatibility clocks where needed
```

Important rule:

> **Deadlines and durations use monotonic time, not mutable wall time.**

Update/security freshness checks need an explicit trustworthy-time policy.

Logs should carry enough clock-domain information to remain interpretable after wall-clock adjustments.

Compatibility Realms may need foreign time semantics without changing native timekeeping.

---

# Annex Candidate X-002 — Entropy & Cryptographic Randomness

**Needed before:** networking security, key generation, credentials, package signing workflows  
**0.1 blocker:** Not necessarily  
**M6/security blocker:** Yes

Define:

```text
early-boot entropy
hardware RNG inputs
interrupt/device entropy where appropriate
VM entropy source
CSPRNG / DRBG
per-process/application random service
reseed policy
fork/process semantics
health diagnostics
failure behavior when entropy unavailable
```

Important rules:

> **Do not expose raw hardware RNG output directly as the system random API.**

> **Cryptographic random service is a security mechanism, not an ordinary extension provider.**

VM/QEMU development must have a reliable entropy story so test and release behavior do not diverge dangerously.

---

# Annex Candidate X-003 — Local Users, Sessions & Ownership

**Needed before:** multi-user desktop, real login, enterprise/shared-device use  
**0.1 blocker:** No, single development owner is sufficient  
**Consumer blocker:** Yes

Current architecture says:

```text
identity != authority
```

which is correct, but user/session semantics remain underspecified.

Need explicit concepts for:

```text
machine owner
local user
guest
login session
locked session
remote session
service identity
AppIdentity
fast user switching
session-scoped UI/services
per-user Provider Bindings
per-user grants
per-user secrets
```

Questions to settle:

- Is Layer 1/2/3 selected per user, per session, or machine?
- Who may change another user's grants?
- What happens to user capabilities when a session locks?
- Which services are machine-scoped vs session-scoped?
- How are background apps/services attributed after logout?
- How are local credentials recovered/reset without destroying encrypted user data?

Do not reintroduce Unix `uid == authority`.

Identity remains an attribute used in policy and ownership records.

Capabilities remain runtime authority.

---

# Annex Candidate X-004 — System Power State / Suspend / Resume

**Needed before:** serious laptop use  
**0.1 blocker:** No  
**Real-hardware consumer blocker:** Yes

E-023 covers power policy, but not full machine state transitions.

Need architecture for:

```text
idle
screen-off
device low-power
suspend-to-RAM
hibernate if supported later
resume
wake sources
thermal emergency
battery-critical shutdown
```

Cross-system concerns:

```text
driver quiesce/resume
storage durability barrier
network session continuity
audio/video pause
GPU restoration
capability/session state
clock discontinuity
lifecycle/update exclusion
```

Suspend must be treated like a coordinated state transition, not a magic firmware call.

---

# Annex Candidate X-005 — Hypervisor / Virtualization Architecture

**Needed before:** E-022 VM fallback, strong development VMs, some enterprise use  
**0.1 blocker:** No  
**Compatibility blocker:** Eventually

E-022 requires a VM fallback but does not yet define:

```text
hypervisor location
VM object model
vCPU/memory capabilities
device virtualization
IOMMU assignment
virtio/paravirtual interfaces
snapshot/checkpoint
VM lifecycle
host/guest resource accounting
secure guest integration
```

Recommended high-level rule:

> **Virtual machines are Jobs/resources under the same capability and lifecycle model, not a separate privileged universe.**

Whether the hypervisor is:

```text
kernel-integrated mechanism
small privileged monitor
userspace VMM over virtualization primitives
```

can remain an implementation decision until required.

---

# Annex Candidate X-006 — Storage Encryption Key Lifecycle

**Needed before:** consumer/private data release  
**0.1 blocker:** No

E-010 supports encryption and E-009 has Secret Vault concepts.

The connection needs explicit design:

```text
machine keys
user keys
dataset keys
key wrapping
password-derived recovery
hardware-backed keys when available
owner recovery key
key rotation
lost credential behavior
multi-user separation
backup/restore
secure erase semantics
```

Critical rule:

> **Authentication reset and data-encryption key recovery are separate problems.**

A forgotten password should not accidentally mean either:

```text
all encryption defeated
```

or:

```text
data permanently destroyed
```

without an explicit recovery policy.

---

# Annex Candidate X-007 — Globalization, Text & Input Methods

**Needed before:** consumer/global desktop  
**0.1 blocker:** No

E-017 includes text rendering and accessibility but not the whole text platform.

Eventually define:

```text
Unicode handling
normalization expectations
font fallback
bidirectional text
complex shaping
input methods / IME
keyboard layouts
locale
number/date formatting
timezone presentation
language packs
text accessibility
```

Avoid allowing filesystem/application identity semantics to depend on locale-sensitive string comparison.

Canonical identifiers should remain locale-independent.

---

# Annex Candidate X-008 — IPC Deadlock / Reentrancy Discipline

**Needed before:** M2 service graph growth  
**0.1 blocker:** Potentially yes

E-008 has:

```text
sync IPC
timeouts
cancellation
bounded scheduling donation
```

but implementation rules should explicitly forbid accidental system-wide RPC deadlocks.

Recommended rules:

- Avoid synchronous RPC while holding non-local/global locks.
- Every synchronous protocol has defined reentrancy semantics.
- Work Context carries causal call identity/depth.
- Runtime/dev builds detect recursive/cyclic synchronous call chains where feasible.
- Services must not rely on infinite IPC queueing.
- Deadlines/cancellation propagate consistently.
- Direct-call optimization preserves the same reentrancy semantics.

This is an implementation discipline annex, not a new IPC architecture.

---

# 10. Important Areas Already Covered Well — Do Not Redesign

The audit specifically recommends **not reopening** the following.

## Capability model

Strong and coherent.

Do not add Unix-root style ambient authority for convenience.

---

## Userspace driver direction

Strong.

Do not move ordinary third-party drivers into the kernel because initial implementation is easier there.

---

## Lifecycle/update model

Very strong.

Do not invent separate app/driver/plugin/model update engines.

---

## Storage generations / rollback

Strong.

Do not postpone all recovery work until after features.

E-025 correctly introduces rollback early.

---

## Typed API/IDL

Strong.

Do not allow hand-written protocol sprawl past bringup.

---

## `.sion` package direction

Coherent.

Exact binary layout may remain open.

The logical package model is sound.

---

## Graphics surface architecture

Good.

Software framebuffer bringup is compatible with the final model.

---

## Media architecture

Good.

Do not force audio/video into one universal execution engine.

---

## Compatibility architecture

Strong.

Do not attempt a direct permanent Win32 implementation during early bringup.

Bootstrap through existing compatibility technology later where practical.

---

## Resource model

Strong.

Do not implement full E-023 policy during 0.1.

Preserve Job accounting and measure early.

---

## Extension architecture

Strong after final Provider Binding pass.

Do not implement large public extension ecosystem before native platform maturity.

---

## Long-term evolution model

Strong.

Do not prematurely implement compatibility retirement machinery before a Stable API level even exists.

---

# 11. Overengineering Audit

A large architecture document can become dangerous if every designed mechanism is treated as an immediate implementation requirement.

The following are intentionally **future mechanisms**.

They are not 0.1 requirements.

---

## Causal QoS / full E-023 pressure system

**Keep architecture. Defer full implementation.**

0.1 only needs:

```text
Jobs
basic accounting
simple scheduler
basic pressure observation
```

---

## Full compatibility personalities

**Keep architecture. Defer implementation.**

No Wine/Linux personality before native platform works.

---

## Direct Win32/NT host adaptation

**Long-term goal only.**

Do not replace mature compatibility projects for ideological purity.

---

## ISA translation

**Future.**

Independent architecture is correct.

No need before ARM64/foreign-ISA use case.

---

## AI Session Risk Graph

**Keep coarse concept. Do not build full formal taint tracking.**

Use:

```text
coarse data classes
provenance
egress gates
session has-seen-sensitive flags
```

Avoid universal byte-level information-flow machinery.

---

## AI Memory

**Future.**

Implement only after one useful safe AI vertical slice exists.

---

## WebAssembly Extension Runner

**Optional.**

Do not make 0.1 depend on a Wasm ecosystem.

---

## Verified Microextensions

**Future specialized optimization.**

Do not build a custom eBPF-like runtime until a concrete need exists.

---

## Replay Debugging

**Scoped future tool.**

Do not attempt universal deterministic replay of the whole OS.

---

## Compatibility Capsules / historical API retirement

**Long-term.**

No reason to build them before Evrosion has historical APIs.

---

## Advanced storage datasets

**Future.**

Do not let the final storage vision block M3 generation rollback.

---

## CXL / NUMA / advanced memory tiers

**Future.**

Architecture remains prepared.

---

## Full cryptographic agility infrastructure

**Design the format IDs early.**

Implement migrations only when real algorithms/keys exist.

---

# 12. Open Implementation Choices That Should Remain Open

These should **not** be prematurely frozen.

## Exact kernel implementation details

Open:

```text
run queue structure
scheduler algorithm details
allocator implementation
capability table representation
page-table abstraction details
lock implementation
```

Stable behavior matters more.

---

## Exact bootloader implementation

Architecture requires UEFI handoff, verified generation selection and recovery.

Exact loader code/project can remain open.

---

## Exact initial storage backend

Only final E-010 contract boundaries matter.

---

## Exact `.sion` physical layout

Logical contents are decided.

Binary/container encoding may evolve during bringup.

---

## Exact IDL wire encoding

Must be versionable, bounded and testable.

Do not stabilize wire layout too early.

---

## Exact compositor implementation

Surface contract is stable direction.

Renderer/compositor data structures are not.

---

## Exact initial fonts/text engine

Open.

Must not block later accessibility/globalization.

---

## Exact network stack implementation

Userspace architecture is chosen.

Whether initially built from existing Rust components or custom code can remain an implementation choice subject to licensing/security/performance review.

---

## Exact AI provider

Explicitly not architectural.

---

## Exact compatibility projects

Wine/Proton/FEX/etc. may change with time.

Architecture is the personality/realm boundary.

---

## Exact build backend

`ev` is the stable UX.

Underlying engine remains replaceable.

---

# 13. Potential Naming / Concept Collisions

These are not architectural contradictions but should be cleaned before implementation documentation hardens terminology.

## "Root"

Evrosion does not use Unix root as general authority.

But the design uses:

```text
Root Supervisor
root capabilities
root trust
```

These are legitimate but can confuse contributors.

Recommendation:

Use explicit phrases consistently:

```text
Bootstrap Authority Set
Root Supervisor
Trust Root
```

and avoid saying simply "root" when the meaning is ambiguous.

---

## "Generation"

Used primarily for system generations.

Avoid casually calling every application version a generation.

Use:

```text
System Generation
Realm Generation
State Epoch
Package Version
```

explicitly.

---

## "Capability"

Use only for non-forgeable authority/resource references.

Do not casually use capability to mean:

```text
hardware feature
software feature
provider ability
```

in security-sensitive documentation without qualifiers.

Use:

```text
hardware capability/feature
security capability
contract feature
```

where needed.

---

## "Session"

Currently may mean:

```text
user login session
AI Session
network session
media session
```

Always qualify the type in architecture docs.

---

# 14. Policy Layering Audit

Evrosion has:

```text
owner policy
current responsibility layer
per-user preferences
application manifests
enterprise policy
service policy
resource policy
AI policy
```

There is no contradiction, but implementation should define explicit ownership and precedence per domain.

Do **not** create one universal policy language immediately.

Recommended approach:

- Each domain defines policy inputs and precedence.
- Owner sovereignty remains constitutional.
- Enterprise policy only has authority when the organization/device ownership model grants it.
- Application manifests request; they do not outrank user/system policy.
- Current Layer determines default protection envelope.
- Trusted Control is the authority-escalation UI.

A generic future policy language may emerge only if repeated semantics justify it.

---

# 15. Identity Audit

Evrosion correctly separates identity from authority.

Important identities already implied:

```text
Machine
User
Login Session
AppIdentity
Service Identity
Driver Package
Extension Identity
Provider Identity
Compatibility Realm
AI Session
Build ID
System Generation
```

Recommendation:

Create a small **Identity Taxonomy** document before M5.

It should answer:

```text
Which identities are stable?
Which are reboot-local?
Which are cryptographically bound?
Which are user-visible?
Which may own durable state?
Which can be targets of grants?
```

Do not turn this taxonomy into a second authority system.

---

# 16. State Ownership Audit

One of the strongest design patterns across Evrosion is:

```text
immutable implementation
+
explicit durable state
```

This appears in:

```text
services
apps
extensions
compatibility realms
system generations
AI models
```

The audit recommends formalizing one universal question for every component:

> **Who owns this state, what is its schema epoch, and what happens when the implementation disappears?**

This should become part of component manifests or architecture review where applicable.

---

# 17. Boot / Recovery Audit

Overall structure is sound.

Important invariants to preserve during implementation:

```text
Boot selects immutable generation.
Pending generation never becomes Known Good merely because kernel started.
Recovery can boot without normal shell/AI/store/network.
Known Good cannot be garbage-collected accidentally.
Recovery does not modify user data merely to repair system.
Layer 3 owner choices remain available.
```

Additional recommendation:

Define a minimal **Boot Health Contract** before M3 implementation.

It should specify which conditions constitute:

```text
Booted
Healthy Enough for probation
Known Good
```

Avoid letting every service independently decide that a generation is healthy.

E-019 already defines critical/degraded/optional health classes; M3 needs a concrete initial subset.

---

# 18. Storage Audit

Architecture is strong.

Remaining considerations:

```text
key lifecycle
backup/restore
secure erase semantics
removable media trust
case sensitivity / normalization policy
user-visible path semantics
```

Only key lifecycle is architecture-critical before consumer use.

The rest may evolve under E-010 contracts.

---

# 19. Networking Audit

Strong conceptual architecture.

Before M6 implementation, explicitly decide:

```text
system time dependency for TLS/update freshness
entropy source
certificate/root trust storage
network namespace/session ownership
firewall policy ownership
DNS privacy defaults
```

No redesign required.

---

# 20. Graphics / Input Audit

Strong.

Additional considerations before consumer maturity:

```text
input-method architecture
secure input path
clipboard/data-transfer service
display hotplug ownership
screen capture privacy indicators
remote desktop / virtual display
```

Most fit naturally inside E-017/E-009 without new global mechanisms.

---

# 21. Audio / Media Audit

Strong.

Before implementation, keep the distinction between:

```text
hard-ish real-time audio
async timestamped media/video
```

Do not merge them for API neatness.

Additional future topics:

```text
media key routing
privacy indicators for mic/camera
Bluetooth timing
DRM-protected media if ever supported
```

No core issue.

---

# 22. Compatibility Audit

E-022 is internally coherent.

Important implementation guardrails:

```text
foreign "root" stays realm-local
foreign self-updater stays realm-local
foreign kernel driver never enters Evrosion kernel
VM transition is explicit
quirks remain scoped
native AppIdentity wraps foreign app
```

Additional future issue:

> VM licensing and guest-OS provisioning are product/legal concerns, not architecture.

Keep them separate.

---

# 23. AI Audit

E-021 has a good security philosophy.

Required final implementation clarifications:

1. Split logical AI control plane; avoid god broker.
2. Action approval binds canonical object/action identity.
3. Durable memory never becomes instruction authority merely by persistence.
4. Session sensitivity labels conservatively propagate after seeing private data.
5. Long-running missions use expiring authority leases.
6. Child agents cannot widen authority.
7. External content can reduce authority but never enlarge it.
8. New external files/apps begin AI-quarantined.
9. Trusted source means easier information ingestion, never authority.
10. AI failure means AI unavailable, not OS unavailable.

No reason to reopen the overall architecture.

---

# 24. Performance Audit

E-023 is ambitious but well-scoped by E-025.

Risks to avoid:

```text
global priority number
policy daemon in fast path
foreground = infinite priority
background = permanently crippled
resource laundering through services
unbounded burst credits
```

Recommended early implementation sequence:

```text
Job accounting
↓
simple CPU fair scheduling
↓
basic memory accounting
↓
basic I/O accounting
↓
pressure metrics
↓
only then causal QoS/burst policy
```

---

# 25. Modularity / Extension Audit

E-024 final version resolves the major historical plugin problems.

Keep these rules strict:

```text
provider discovery != authority
new package cannot self-bind globally
native in-process extension = trust fusion
filter/interposition chain bounded
registry reconstructable
resolver not data path
kernel extension narrow
```

No core issue.

---

# 26. Long-Term Evolution Audit

E-026 is coherent and should be treated as constitutional guidance, not as a large implementation epic.

Do **not** implement all governance machinery at once.

Before coding starts, only the following E-026 pieces are immediately valuable:

```text
Architecture Index
ADR template
temporary-exception register
basic architecture fitness-test directory
```

API retirement/capsules can wait until APIs actually age.

---

# 27. Build Readiness Audit

## Ready now

The following are sufficiently defined to begin M0/M1 implementation:

```text
initial architecture target
kernel role
memory direction
thread/process/Job model
capability direction
IPC direction
language policy
build/tooling direction
debugging direction
initial scope
```

---

## Must define before M2

```text
A-001 Root Authority Custody & Reconstitution
X-008 IPC deadlock/reentrancy discipline
initial Service Identity / bootstrap identity conventions
minimal Bootstrap Authority Set
```

---

## Must define before M3

```text
initial Boot Health Contract
minimal durable journal semantics
exact initial storage backend choice
generation metadata layout
recovery authority path
```

---

## Must define before M4/M5

```text
minimal trusted file-picker authority flow
durable grant persistence model
basic Identity Taxonomy
minimal AppIdentity fields
basic text/font/input contract
TOCTOU-safe resource grant semantics
```

---

## Must define before M6 networking

```text
Time & Chronology Architecture
Entropy / CSPRNG Architecture
certificate/root-trust storage
minimal network security policy
```

---

## Must define before first serious laptop target

```text
Suspend/Resume Architecture
Power-state coordination
Storage encryption key lifecycle
Multi-user/session model
```

---

## Must define before E-022 VM fallback

```text
Hypervisor/VM object model
host/guest capability model
VM resource accounting
virtual device model
```

---

## Must define before consumer maturity

```text
Globalization / text / IME
multi-user/session UX
accessibility baseline
key recovery
backup/restore UX
privacy indicators
reference hardware support matrix
```

---

# 28. Proposed Audit Action Register

These are the actionable results of this audit.

## A-001 — Define Root Authority Custody

**When:** Before M2  
**Outcome:** Root Supervisor can fail/restart without losing or multiplying initial authority.

---

## A-002 — Amend E-021 Implementation Note

**When:** Before AI implementation  
**Outcome:** AI Authority Broker is a logical control plane, not one all-powerful process.

---

## A-003 — Define Durable Grant Records

**When:** Before M5  
**Outcome:** Runtime capabilities are re-minted from explicit durable grant policy rather than serialized raw handles.

---

## A-004 — Define TOCTOU-Safe Approval Binding

**When:** Before trusted picker/destructive approvals/AI actions  
**Outcome:** User approval refers to stable object/action identity.

---

## A-005 — Define Time Architecture

**When:** Before M6  
**Outcome:** Monotonic/UTC/RTC/sync/freshness behavior is explicit.

---

## A-006 — Define Entropy Architecture

**When:** Before M6 security/network use  
**Outcome:** System CSPRNG and entropy bootstrap are explicit.

---

## A-007 — Define User / Session Model

**When:** Before shared/consumer desktop  
**Outcome:** Owner/user/guest/session identities and durable state scopes are clear.

---

## A-008 — Define Suspend / Resume Coordination

**When:** Before serious laptop support  
**Outcome:** Device/services/storage/clock state transitions are coherent.

---

## A-009 — Define Virtualization Boundary

**When:** Before VM compatibility path  
**Outcome:** VM execution participates in capabilities, Jobs and lifecycle rather than becoming a separate architecture.

---

## A-010 — Define Storage Encryption Key Lifecycle

**When:** Before protecting real user data  
**Outcome:** Key recovery/rotation/multi-user semantics are explicit.

---

## A-011 — Define Globalization / Text Annex

**When:** Before consumer internationalization  
**Outcome:** Unicode/IME/font/locale behavior does not become ad-hoc UI-specific code.

---

## A-012 — Define IPC Reentrancy Discipline

**When:** Before M2 service graph grows  
**Outcome:** Sync IPC does not create systemic deadlock patterns.

---

## A-013 — Create Identity Taxonomy

**When:** Before M5  
**Outcome:** Machine/User/Session/App/Service/Realm/AI identities have clear lifetime and persistence.

---

## A-014 — Create Initial Boot Health Contract

**When:** Before M3 generation rollback  
**Outcome:** "Started", "probation", and "Known Good" have concrete initial criteria.

---

## A-015 — Create Architecture Governance Files

**When:** Before serious implementation growth  
**Outcome:** Repository contains:

```text
ARCHITECTURE_INDEX.md
/architecture/adr/
/architecture/exceptions/
/tests/architecture/
```

or equivalent.

---

# 29. What Should Remain Locked

The audit recommends treating the following as **architectural invariants unless extraordinary evidence appears**:

```text
Capability-first authority
No ambient root
Layer 3 owner sovereignty
Mechanism-focused kernel
Userspace drivers/services by default
Typed contract/IDL direction
IPC + shared-memory split
Job hierarchy
Immutable program/system content
Explicit durable state
System Generations + Known Good
Transactional lifecycle
Recovery independence
No mandatory cloud/account/telemetry
AI optional and non-authoritative
Compatibility outside native core
Native software pays no compatibility tax
Extension Points instead of arbitrary hooks
Provider discovery separate from provider binding
Resource policy outside fast path
Rust internal / language-neutral public boundary
QEMU-first bringup
Architecture-complete feature-minimal 0.1
Stable laws / replaceable implementations
```

---

# 30. What Is Still Flexible

The following should remain implementation choices until evidence forces a decision:

```text
exact scheduler algorithm
exact allocator
exact storage backend
exact on-disk filesystem
exact .sion container encoding
exact IDL wire format
exact compositor renderer
exact UI toolkit
exact font/text engine
exact network-stack implementation
exact hypervisor implementation
exact AI provider
exact compatibility projects
exact build backend beneath `ev`
exact extension runner set
exact hardware reference machine after QEMU
```

This flexibility is intentional.

---

# 31. Major Architectural Strengths

The audit considers these the strongest parts of Evrosion.

## 1. Capability model is not an afterthought

Security is built into process/service/file/device/app/AI/extension architecture.

---

## 2. Recovery is not an afterthought

System Generations, Known Good, Durable Operations and health gates are early architecture, not emergency tooling.

---

## 3. Failure is expected

Services, drivers, apps, extensions and compatibility workloads can fail independently.

---

## 4. Compatibility is contained

Foreign OS behavior does not define native Evrosion.

---

## 5. AI is constrained structurally

Prompt injection is treated as inevitable input risk rather than solved by magical prompts.

---

## 6. Resource control has one workload hierarchy

Jobs provide a coherent basis for scheduling/accounting without pretending all resources have one priority number.

---

## 7. Evolution is designed

Contracts, API levels, migration, rollback and compatibility fixtures provide an explicit long-term story.

---

## 8. Ownership and safety are not treated as opposites

Layer 1/2 can protect.

Layer 3 preserves deliberate owner control.

---

# 32. Major Long-Term Risks

These are not flaws in the current documents.

They are the risks most likely to damage Evrosion during implementation.

## Risk 1 — Too many services

Microkernel enthusiasm can become process explosion.

Countermeasure:

```text
boundary justification test
adaptive co-location
E-026 always-on-service budget
```

---

## Risk 2 — Capability UX becomes unbearable

A technically pure security system can become unusable if every action prompts.

Countermeasure:

```text
semantic grants
picker grants
scoped durable policy
layer-specific defaults
Trusted Control only at meaningful boundaries
```

---

## Risk 3 — Temporary bringup shortcuts leak into APIs

Countermeasure:

```text
E-025 temporary-implementation/permanent-boundary rule
Internal stability class
architecture exception register
```

---

## Risk 4 — Compatibility consumes the project

Countermeasure:

```text
native platform first
Wine/Proton/Linux tech reuse
personality boundary
VM fallback
no requirement for perfect compatibility
```

---

## Risk 5 — Hardware support consumes the project

Countermeasure:

```text
QEMU first
one real reference machine
one device family at a time
userspace drivers
hardware capability tiers
```

---

## Risk 6 — AI creates a second operating-system control plane

Countermeasure:

```text
AI proposals only
same E-009 caps
same E-010/E-019 actions
no god broker
native typed tools
AI optional
```

---

## Risk 7 — Stable API surface grows too quickly

Countermeasure:

```text
Internal/Preview before Stable
API budget
frozen compatibility tests
history moves outward
```

---

## Risk 8 — Architecture becomes documentation-only

Countermeasure:

```text
architecture fitness tests
failure injection
compatibility fixtures
rollback tests
capability denial tests
```

---

# 33. Recommended Immediate Repository Artifacts

Before or during M0, create these lightweight architecture artifacts.

```text
/architecture/ARCHITECTURE_INDEX.md
/architecture/INVARIANTS.md
/architecture/adr/0000-template.md
/architecture/exceptions/README.md
/architecture/glossary.md
/tests/architecture/README.md
```

They do not need elaborate tooling.

Their purpose is to prevent design knowledge from becoming scattered.

---

# 34. Recommended Initial Architecture Fitness Tests

The earliest automated cross-system tests should be:

```text
AF-001 Boot reaches kernel deterministically
AF-002 User process fault does not crash kernel
AF-003 No capability → operation denied
AF-004 Capability transfer enables only transferred right
AF-005 Attenuated cap cannot regain removed rights
AF-006 Service crash leaves unrelated service alive
AF-007 Root Supervisor restart preserves exact bootstrap authority set
AF-008 Malformed IPC rejected
AF-009 Shared Memory Object cannot be mapped without capability
AF-010 Broken System Generation rolls back to Known Good
AF-011 Interrupted durable write produces old or new committed state
AF-012 Graphical app crash leaves shell alive
AF-013 File picker grants exactly selected object
AF-014 Provider Binding swap preserves contract behavior
AF-015 Reproducible image check
```

This converts the architecture into executable reality from the beginning.

---

# 35. Suggested Pre-M0 Decisions

The audit does **not** recommend another giant architecture phase.

Before coding, only settle the handful of things that would otherwise immediately block M0/M1/M2.

Recommended sequence:

```text
1. Architecture Index + glossary
2. Root Authority Custody note
3. IPC deadlock/reentrancy note
4. Initial object/capability terminology
5. Initial repository layout
6. M0 exit-test script
7. Start code
```

Do not spend months writing annexes for features that M0 does not use.

The remaining annexes should be designed just before their dependency milestone.

---

# 36. Final Build-Readiness Decision

## Architecture completeness

**PASS**

The system has a coherent end-to-end architecture.

---

## Security model completeness

**PASS WITH CONNECTIVE ACTIONS**

Main authority model is sound.

A-001/A-003/A-004 should be completed before their milestones.

---

## Recovery/lifecycle completeness

**PASS**

One of the strongest areas.

---

## Native app platform completeness

**PASS FOR BRINGUP**

Enough is defined for M4/M5.

---

## Hardware strategy completeness

**PASS**

E-025 deliberately limits initial scope.

---

## Compatibility strategy completeness

**PASS FOR LATER IMPLEMENTATION**

No need to implement now.

---

## AI strategy completeness

**PASS WITH A-002 CLARIFICATION**

Architecture is sound.

Broker centralization must be constrained explicitly.

---

## Performance strategy completeness

**PASS**

Full implementation intentionally deferred.

---

## Evolution strategy completeness

**PASS**

E-026 gives clear long-term governance.

---

## Ready to begin M0?

> **YES.**

The remaining audit actions do not justify delaying M0.

A-001 and X-008 should be settled before M2 begins.

Time/entropy/session/power/virtualization/globalization can be designed just before the milestone that actually needs them.

---

# 37. Final Verdict

Evrosion has moved beyond:

> "an idea for an operating system."

It now has a coherent architectural spine.

The strongest property is not that every subsystem is novel.

It is that the subsystems agree about the same small set of laws:

```text
authority is explicit
state is explicit
contracts are explicit
failures are expected
updates are reversible
policy is replaceable
history is contained
optional systems stay optional
the owner remains final authority
```

The architecture should now resist the temptation to design forever.

The next major source of truth must increasingly become:

```text
running code
tests
fault injection
measurement
```

rather than additional architecture prose.

The audit therefore recommends:

> **Begin E-025 M0 implementation after the small pre-M0 governance/root-authority/IPC notes are created.**

Do not reopen the 26 core chapters unless implementation evidence proves one of their invariants wrong.

From this point forward:

> **The architecture should be challenged by code.**

---

# 38. Audit Action Summary

## Before M2

```text
A-001 Root Authority Custody & Reconstitution
A-012 IPC Reentrancy / Deadlock Discipline
minimal identity/bootstrap conventions
```

## Before M3

```text
A-014 Initial Boot Health Contract
minimal generation metadata/storage backend choices
```

## Before M5

```text
A-003 Durable Grant Persistence
A-004 TOCTOU-Safe Approval Binding
A-013 Identity Taxonomy
```

## Before M6

```text
A-005 Time & Chronology
A-006 Entropy / CSPRNG
```

## Before laptop/consumer hardware

```text
A-007 User/Session Model
A-008 Suspend/Resume
A-010 Storage Encryption Key Lifecycle
A-011 Globalization/Text
```

## Before VM compatibility

```text
A-009 Virtualization Architecture
```

## Before AI implementation

```text
A-002 Non-Godlike AI Control Plane
```

---

# Audit Conclusion

**Core architecture status:** READY FOR IMPLEMENTATION  
**Fundamental redesign required:** NO  
**High-priority connective issues:** SMALL, IDENTIFIED, BOUNDED  
**Recommended next phase:** E-025 M0 implementation preparation and coding

**Evrosion E-001 through E-026 remain valid.**
