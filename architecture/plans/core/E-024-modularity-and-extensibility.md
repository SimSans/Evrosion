# Evrosion — E-024 Modularity & Extensibility Architecture

**Status: ARCHITECTURAL DIRECTION DECIDED AND CLOSED**

Evrosion will use a:

> **Capability-Routed Extension Fabric with Typed Extension Points, Explicit Provider Bindings, Replaceable Implementations, Adaptive Isolation, and Lifecycle-Managed Composition**

The central rule is:

> **Extend contracts, not implementation internals.**

Evrosion should remain highly extensible without turning into an operating system whose stability depends on arbitrary hooks, global plugin order, hidden shared state, or third-party code running inside privileged processes.

---

# E-024.1 — What Modularity Means

Modularity does not mean:

```text
many DLLs
many processes
many packages
```

A subsystem is genuinely modular when it can be:

```text
understood
replaced
updated
restarted
tested
isolated
versioned
```

without forcing unrelated components to change.

---

# E-024.2 — Modularity Exists for Independent Change

The purpose of modularity is:

> **Allow pieces of Evrosion to evolve independently while preserving coherent contracts.**

Modularity is not a goal to maximize component count.

---

# E-024.3 — Extension Points

Evrosion should expose explicit:

> **Extension Points**

An Extension Point is a stable typed contract describing a place where one or more alternative implementations may provide functionality.

Possible examples include:

```text
file preview provider
thumbnail provider
archive handler
codec
desktop widget
search provider
authentication provider
filesystem implementation
device-class driver
network policy provider
AI connector
compatibility runtime
power policy provider
shell component
```

The initial set belongs to E-025.

---

# E-024.4 — No Arbitrary Global Hooks

Evrosion should reject a general plugin model based on:

```text
patch random function
intercept undocumented callback
modify internal table
load into arbitrary process
depend on installation order
```

Extensions depend on declared contracts.

Not implementation accidents.

---

# E-024.5 — Extension Points Use E-015 Contracts

An Extension Point should be a specialized E-015 platform contract.

It describes:

```text
interface
version
imports
exports
capability requirements
lifecycle expectations
state model
resource expectations
failure semantics
```

Evrosion does not need a separate unrelated plugin-API universe.

---

# E-024.6 — Typed Contracts

Extension contracts should be:

```text
typed
language-neutral
versioned
machine-readable
testable
```

IDL tooling generates language bindings, validation, documentation and conformance fixtures where practical.

---

# E-024.7 — Extension Surface Budget

Every public Extension Point becomes a long-term compatibility obligation.

Therefore Evrosion should maintain an:

> **Extension Surface Budget**

Creating a new Stable Extension Point requires architectural justification.

---

# E-024.8 — Do Not Extension-Point Everything

Internal implementation boundaries should remain Internal or Preview until real evidence shows that third-party replacement/extensibility provides durable value.

Bad:

```text
make every internal callback public
```

Preferred:

```text
expose only coherent semantic roles
```

---

# E-024.9 — Extension Point Maturity

Extension contracts follow E-015 stability classes.

Conceptually:

```text
Internal
 ↓
Experimental
 ↓
Preview
 ↓
Stable
```

Stable is an expensive promise.

---

# E-024.10 — Stable Extension Point Criteria

Before becoming Stable, an Extension Point should demonstrate:

```text
coherent semantics
clear authority model
bounded failure behavior
bounded performance expectations
versioning strategy
conformance-test feasibility
real ecosystem value
plausible independent implementations
```

If these cannot be defined:

> Do not stabilize it.

---

# E-024.11 — Public API Creation Is Deliberate

A convenient internal boundary does not automatically deserve public ecosystem status.

Evrosion should prefer delaying an extension point over permanently freezing a bad abstraction.

---

# E-024.12 — Extension Manifest

An extension package contains a declarative manifest.

Conceptually:

```text
Extension:
    identity

Provides:
    ev.preview.image@2

Consumes:
    ev.storage.file@4
    ev.graphics.image@3

Requests:
    FILE_READ
    GPU_DECODE

Execution:
    isolated-native

State:
    private-versioned

Lifecycle:
    restartable

Failure:
    bypass
```

---

# E-024.13 — Declared Imports and Exports

An extension explicitly declares:

```text
what it provides
what it consumes
```

It should not discover arbitrary internal services by scanning the machine.

---

# E-024.14 — Explicit Capability Routing

Capabilities are routed deliberately between consumer and provider.

An extension receives only capabilities that have a valid route.

Existence on the machine does not create authority.

---

# E-024.15 — Effective Extension Authority

Conceptually:

```text
Host Delegation
      ∩
Extension Declared Requirements
      ∩
User / Policy Grant
      ∩
Current Security Layer
      ∩
Invocation Scope
      =
Effective Extension Authority
```

Every term can reduce authority.

None may silently create additional authority.

---

# E-024.16 — No Accidental Host Privilege Inheritance

A File Manager may possess broad capabilities.

A preview provider invoked for one file should normally receive:

```text
READ selected-file
```

not:

```text
all File Manager authority
```

---

# E-024.17 — Invocation-Scoped Capabilities

Whenever practical, extensions should receive capabilities scoped to the current invocation.

Example:

```text
Thumbnail Provider
    ↓
READ photo.jpg
```

rather than a persistent right to every image on the machine.

---

# E-024.18 — Extension Code Is Ordinary Managed Software

Extensions remain subject to:

```text
E-009 capabilities
E-019 lifecycle
E-020 diagnostics
E-023 resource contracts
```

They do not receive a special escape hatch merely because they are called plugins.

---

# E-024.19 — Provider Discovery Is Not Provider Authority

This is a core invariant.

The system may discover:

```text
Provider A implements ev.preview.image@2
Provider B implements ev.preview.image@2
Provider C implements ev.preview.image@2
```

That does not determine which provider is actually allowed to serve the contract.

---

# E-024.20 — Provider Catalog

Installed immutable extension/package manifests form a:

> **Provider Catalog**

or reconstructable registry/index.

The catalog answers:

> Which installed packages claim compatible implementations of this contract?

---

# E-024.21 — Provider Binding

Actual provider selection is represented separately as a:

> **Provider Binding**

A Provider Binding may record:

```text
contract identity/version
selected provider identity/version
scope
user/system/enterprise policy
selection reason
lifecycle transaction
health state
```

---

# E-024.22 — New Providers Cannot Self-Promote

Installing a package that declares:

```text
provides ev.foo@2
```

must not automatically replace the currently active provider.

Provider registration is discovery.

Provider binding is authority.

---

# E-024.23 — Provider Replacement Is Explicit

Changing:

```text
Provider A
→
Provider B
```

is an E-019 lifecycle operation.

It may include:

```text
compatibility validation
staging
startup
health probation
connection routing
commit
rollback
```

---

# E-024.24 — Provider Changes Are Observable

Evrosion should be able to explain:

> RAW image previews are now provided by ExampleRAW 3.2 instead of the built-in provider.

No silent global behavior mutation.

---

# E-024.25 — Scoped Provider Bindings

Provider selection may be scoped.

Possible scopes:

```text
application
workspace/project
user
machine
system generation
```

where the Extension Point semantics permit it.

---

# E-024.26 — Protected Provider Classes

Security-critical or boot-critical Extension Points may restrict eligible providers more strongly.

Examples might include:

```text
boot storage provider
trusted input provider
secure-attention provider
root trust provider
```

The exact set remains narrow.

---

# E-024.27 — Provider Resolver

A logical:

> **Provider Resolver**

computes which provider can satisfy a request.

It may consider:

```text
Provider Binding
contract compatibility
user preference
system policy
enterprise policy
hardware
health
availability
```

---

# E-024.28 — Resolver Is Not the Authority Source

The Provider Resolver does not invent authority.

It evaluates:

```text
immutable manifests
durable Provider Bindings
policy
health
```

The binding/policy state remains authoritative.

---

# E-024.29 — Resolver Is Not on the Data Path

After a client has received a routed endpoint to a provider:

```text
Client ↔ Provider
```

normal calls should not flow through the Provider Resolver.

---

# E-024.30 — Resolver Failure

If the Provider Resolver crashes:

```text
existing connections continue
cached bindings remain valid
new resolution may temporarily fail or use safe cache
resolver restarts
```

The machine does not collapse.

---

# E-024.31 — Registry Is Reconstructable

The provider catalog/index is derived from:

```text
installed immutable manifests
activation state
Provider Bindings
```

If corrupted:

```text
rebuild
```

It is not irreplaceable system truth.

---

# E-024.32 — Provider Binding State Is Small and Durable

Provider Bindings are durable policy/configuration state.

They should be:

```text
structured
journaled
versioned
recoverable
```

using E-010/E-019 durability mechanisms.

---

# E-024.33 — Deterministic Composition

Given the same:

```text
installed packages
Provider Bindings
policy
hardware capability
health state
```

provider resolution should be deterministic.

Avoid mysterious behavior based on filesystem enumeration order.

---

# E-024.34 — Single-Provider Roles

For an Extension Point requiring one implementation:

```text
exactly one selected provider
```

should normally serve the role at a given scope.

---

# E-024.35 — No Mystery Interception Order

Evrosion should never rely on:

```text
whichever plugin loaded first
```

or:

```text
last installed wins
```

for semantic behavior.

---

# E-024.36 — Multi-Provider Contracts

Some Extension Points legitimately support multiple providers.

Examples:

```text
thumbnail provider by format
authentication mechanisms
search sources
```

In that case the contract explicitly defines multi-provider semantics.

---

# E-024.37 — Multi-Provider Semantics

The Extension Point must specify:

```text
selection
ordering
aggregation
conflict handling
parallelism
timeouts
failure behavior
```

rather than leaving behavior implicit.

---

# E-024.38 — Interposition Contracts

Extensions intended to inspect/filter/interpose operations use a specialized:

> **Interposition Contract**

Examples may include:

```text
network policy filter
content scanner
security filter
request transformation
```

---

# E-024.39 — Interposition Is Not a General Hook

An Interposition Contract specifies exactly:

```text
what may be observed
what may be modified
what may be blocked
ordering
deadline
failure action
reentrancy rules
```

There is no general arbitrary call interception facility.

---

# E-024.40 — Filter Chains Are Bounded

Filter/interposition chains should define:

```text
maximum chain depth
per-stage resource budget
per-stage deadline
total deadline
ordering
```

Unbounded plugin chains are prohibited.

---

# E-024.41 — Hard Dependency Cycle Detection

Activation dependencies should be analyzed before activation.

Example:

```text
A requires B
B requires C
C requires A
```

If none can initialize independently:

```text
reject composition
```

Do not discover impossible graphs during boot.

---

# E-024.42 — Synchronous Interposition Cycle Rules

A synchronous filter should not be allowed to recursively call an upstream stage in the same chain unless the contract explicitly defines safe reentrancy.

This avoids:

```text
A waits on B
B calls A
A waits forever
```

---

# E-024.43 — Work Context Detects Runtime Recursion

E-008 Work Contexts should carry enough causal identity to detect or diagnose recursive interposition loops.

E-020 tracing records:

```text
filter chain
stage
latency
deadline
recursive call
```

---

# E-024.44 — Cancellation Propagates Through Filters

If the original operation is cancelled:

```text
cancellation
↓
filter chain
```

must follow the Extension Point's cancellation contract.

A dead client should not leave arbitrary filter work running forever.

---

# E-024.45 — Filter Timeout Semantics

Each Interposition Contract defines what timeout means.

Possible outcomes:

```text
bypass provider
fail operation
fallback provider
fail closed
fail open
```

depending on security semantics.

---

# E-024.46 — Security Filters Usually Fail Closed

For a filter whose purpose is enforcing a security boundary:

```text
filter unavailable
```

should normally mean:

```text
operation denied or safely degraded
```

unless the contract explicitly defines another safe behavior.

---

# E-024.47 — Optional UX Filters May Bypass

A thumbnail beautifier or optional preview filter may safely use:

```text
timeout → bypass
```

The failure model belongs to the specific contract.

---

# E-024.48 — Critical Hot Paths Avoid Arbitrary Chains

Extremely latency-sensitive or safety-critical paths should not accept arbitrary third-party filter chains unless the contract was explicitly designed and budgeted for them.

---

# E-024.49 — Failure Semantics Are Part of Every Extension Point

Every Extension Point must answer:

> What happens if the provider crashes, hangs, times out, returns malformed data, or becomes unavailable?

Possible semantics:

```text
restart
bypass
fallback provider
disable feature
fail operation
```

---

# E-024.50 — Broken Extension Does Not Break Host

Example:

```text
File Manager
 ↓
Thumbnail Provider
 ↓
CRASH
```

Preferred result:

```text
thumbnail unavailable
provider restarted/quarantined
File Manager survives
```

---

# E-024.51 — Extension Quarantine

Repeatedly failing extensions may enter:

> **Extension Quarantine**

Possible triggers:

```text
repeated crash
repeated hang
repeated OOM
deadline violations
malformed protocol
health-check failure
```

---

# E-024.52 — Quarantine Is Not Deletion

Quarantine means:

```text
installed
known
inactive because health policy rejected it
```

The package remains inspectable.

---

# E-024.53 — Quarantine Fallback

Where an alternate provider exists:

```text
quarantine bad provider
↓
activate known-good fallback
```

according to the Extension Point's lifecycle policy.

---

# E-024.54 — Layer 3 Quarantine Override

The owner may deliberately reactivate or force a quarantined provider in Absolute Access.

Evrosion warns.

The owner decides.

---

# E-024.55 — Failure Capsules

E-020 Failure Capsules should include extension-specific information such as:

```text
Extension identity/version
Extension Point
Provider Binding
Runner
Isolation mode
Capabilities
Host/consumer
Resource contract
State epoch
Failure history
Trace slice
```

---

# E-024.56 — Adaptive Isolation

Extensions follow E-001's adaptive-isolation principle.

Default:

```text
unknown / third-party / failure-prone native code
→ isolated
```

---

# E-024.57 — Native Isolated Runner

Normal third-party native extensions should generally execute in a separate:

```text
Job / process
```

with explicitly routed capabilities.

---

# E-024.58 — In-Process Native Code Is Trust Fusion

This is a core invariant.

Loading arbitrary native extension code directly into a host process means:

> **The extension joins the host's memory, crash, and security domain.**

It must never be described as independently sandboxed.

---

# E-024.59 — Co-Location Is Not Merely a Performance Toggle

Moving:

```text
isolated extension
→ native in-process extension
```

is a security/trust-domain change.

Treat it accordingly.

---

# E-024.60 — Native Co-Location Requirements

Native in-process co-location should require deliberate policy and evidence such as:

```text
compatible contract/ABI
trusted publisher/owner decision
conformance success
health history
measured performance benefit
host consent
```

Exact policy can vary by component class.

---

# E-024.61 — Signing Alone Does Not Justify Co-Location

A valid signature establishes provenance.

It does not prove:

```text
bug-free
non-malicious
safe to share host memory
```

E-009 principles remain authoritative.

---

# E-024.62 — Measured Benefit Before Trust Fusion

Do not co-locate simply because:

> Same-process is theoretically faster.

Use profiling.

If isolation overhead is insignificant:

keep isolation.

---

# E-024.63 — Isolation-Class Change Is a Lifecycle Change

Promotion/demotion between:

```text
isolated
sandboxed runtime
trusted co-located
```

should be an E-019-managed activation change.

Rollback remains possible where practical.

---

# E-024.64 — Safe Physical Co-Location

A sandboxed runtime may execute inside the same host process while preserving logical isolation if the runtime actually enforces:

```text
separate memory
typed imports
capability-limited APIs
resource bounds
```

Physical co-location does not necessarily imply native trust fusion.

---

# E-024.65 — Extension Runners

Evrosion should support the generic concept of:

> **Extension Runners**

A runner executes extension code according to a defined execution model.

---

# E-024.66 — Possible Runners

Examples:

```text
Native Isolated Runner
WebAssembly Component Runner
Trusted Native Co-Located Runner
Future Managed Runtime
```

Exact implementations may evolve.

---

# E-024.67 — Runner Is Routed Capability

The extension framework should not hard-code every runtime internally.

Runners may themselves be replaceable routed services under appropriate contracts.

---

# E-024.68 — Contract Independent of Runner

The logical Extension Point should generally survive changing execution strategy.

Example:

```text
ev.preview.image@2
```

could potentially be implemented by:

```text
native process
Wasm component
trusted native component
```

without changing the consumer contract.

---

# E-024.69 — WebAssembly Is Optional

WebAssembly may be useful for portable, capability-limited extensions.

It is not the universal Evrosion extension format.

---

# E-024.70 — WebAssembly Candidate Uses

Possible suitable workloads include:

```text
format processors
small automation modules
widgets
lightweight policy modules
portable tools
AI adapters
```

where performance and runtime capabilities are appropriate.

---

# E-024.71 — Native Code Remains Necessary

Some extensions may require native execution because of:

```text
SIMD
GPU APIs
hardware integration
very low latency
existing native ecosystem
```

Evrosion should not force WebAssembly where it harms the use case.

---

# E-024.72 — Composition Over Inheritance

Extension APIs should prefer:

```text
implement contract A
consume contract B
```

rather than:

```text
subclass giant internal framework object
```

This keeps interfaces language-neutral and versionable.

---

# E-024.73 — Multiple Language Support

Because contracts are language-neutral, extensions may theoretically be implemented in supported languages such as:

```text
Rust
C
C++
Zig
Wasm-supported languages
```

without creating separate operating-system plugin models.

---

# E-024.74 — Rust Remains Preferred Internally

Evrosion's own native extension implementations should continue preferring Rust under E-013.

The public contract remains language-neutral.

---

# E-024.75 — Verified Microextensions

Some future use cases may justify tiny programmable components extremely close to kernel/hot paths.

Evrosion may support:

> **Verified Microextensions**

rather than arbitrary native kernel plugins.

---

# E-024.76 — Verified Microextensions Are Narrow

Potential program classes could include:

```text
NetworkFilter
TraceFilter
ResourcePredicate
DeviceMatcher
```

Only use cases with clearly bounded semantics should be considered.

---

# E-024.77 — Program-Type Contracts

Each microextension program type defines:

```text
typed input context
allowed helpers
allowed outputs
memory bounds
instruction/time bounds
resource budget
failure behavior
```

---

# E-024.78 — Static Verification

Before activation:

```text
program
 ↓
verifier
 ↓
accepted / rejected
```

The verifier proves required safety properties within the chosen execution model.

---

# E-024.79 — No Arbitrary Kernel Memory

Verified Microextensions cannot:

```text
read arbitrary kernel memory
write arbitrary kernel memory
call arbitrary kernel functions
invent capabilities
```

unless an intentionally narrow program contract explicitly exposes a safe equivalent.

---

# E-024.80 — Stable Helpers, Not Kernel Internals

Microextensions see:

```text
stable typed contexts
stable approved helper contracts
```

not raw kernel implementation structures.

---

# E-024.81 — No Ordinary Third-Party Kernel Module ABI

Evrosion should not commit to a permanent public ABI for arbitrary third-party native kernel modules.

That would undermine:

- E-002 kernel minimization
- security
- evolvability
- crash containment
- ABI freedom

---

# E-024.82 — Custom Kernel Is the Ownership Escape Hatch

Layer 3 owners may build and boot custom kernels under E-009/E-012.

Absolute ownership does not require every production kernel to accept arbitrary ring-0 plugins.

---

# E-024.83 — Kernel Internal Modularity Is Separate

Kernel source may remain internally modular.

Example:

```text
scheduler
VM
IPC
capabilities
architecture
```

This is implementation/build modularity.

It is not a public third-party extension ABI.

---

# E-024.84 — Live Kernel Mutation Is Exceptional

Evrosion should not create a generic live-patching framework merely to appear advanced.

Normal kernel updates use E-019 System Generations and reboot.

---

# E-024.85 — Future Emergency Live Patching

A narrowly scoped emergency live-security-patch mechanism may be considered later if evidence justifies the complexity.

It is not foundational to E-024.

---

# E-024.86 — Extension Packages Use `.sion`

Native extensions use normal E-016 package infrastructure.

Conceptually:

```text
PreviewExtension.sion
├── extension manifest
├── code
├── resources
├── provided contracts
├── requested capabilities
├── state schema
└── lifecycle metadata
```

No separate plugin package universe.

---

# E-024.87 — Immutable Code

Installed extension program content is immutable/versioned.

Updates install new versions side-by-side using E-019.

---

# E-024.88 — Explicit Extension State

Durable extension state is stored separately from immutable program content.

Conceptually:

```text
Extension Code
immutable

Extension State
private
versioned
durable as declared
```

---

# E-024.89 — State Migration

Extension updates declare:

```text
state epoch
migration
rollback semantics
```

E-019 Commit Horizon rules apply.

---

# E-024.90 — No Hidden State in Plugin Directories

Extensions should not depend on mutating random files beside their executable as the primary state model.

State belongs to declared storage.

---

# E-024.91 — Extension Lifecycle Uses E-019

Extensions use the standard lifecycle:

```text
acquire
verify
stage
activate
health
commit
rollback
pin
remove
```

There is no separate plugin updater.

---

# E-024.92 — Hot Provider Replacement

Service-style providers may support:

```text
Provider A active
 ↓
start Provider B
 ↓
health check
 ↓
route new work to B
 ↓
drain A
 ↓
commit
```

where the Extension Point permits it.

---

# E-024.93 — Stable Logical Identity

Consumers bind to:

```text
ev.image.thumbnail@2
```

rather than:

```text
/usr/lib/plugin123.so
```

Implementation is replaceable.

Contract identity remains stable.

---

# E-024.94 — Application-Private Extensions

An application may contain internal extension components.

Example:

```text
Video Editor
├── renderer
├── import component
└── effect module
```

These remain private to the application's Job/realm unless explicitly exposed.

---

# E-024.95 — Private Does Not Mean Global

Bundling an extension inside an application does not register it as a machine-wide provider.

Global provider registration is separate.

---

# E-024.96 — Extension Scope

Possible activation scopes include:

```text
application-local
workspace/project
user
machine
```

depending on the Extension Point.

---

# E-024.97 — System-Wide Registration Is Explicit

An extension cannot silently make itself:

```text
global PDF handler
global shell provider
global network filter
global authentication provider
```

during ordinary application installation.

System-wide registration/binding is a separate policy/lifecycle operation.

---

# E-024.98 — Shell Extensibility

E-017 established that the Desktop Shell is replaceable policy rather than trusted display infrastructure.

Users may therefore:

```text
replace whole shell
```

or:

```text
extend shell through declared UI Extension Points
```

---

# E-024.99 — UI Extensions Provide Surfaces

UI extensions should provide:

```text
surface/content
accessibility semantics
declared interactions
```

to the shell.

They do not receive arbitrary access to shell internals.

---

# E-024.100 — UI Extension Failure

A widget crash should normally result in:

```text
widget disappears/restarts
```

not:

```text
desktop crashes
```

---

# E-024.101 — Accessibility Applies to Extensions

UI extension contracts should require semantic accessibility information where applicable.

F-008 remains universal.

---

# E-024.102 — Extensions Use E-023 Resources

Each extension executes under a Job/resource contract.

Evrosion can account:

```text
CPU
memory
GPU
network
storage
```

usage.

---

# E-024.103 — No Plugin Resource Exemption

A broken extension cannot claim:

> I'm only a plugin.

and escape normal resource governance.

---

# E-024.104 — Extension Resource Limits

An Extension Point may define expected budgets such as:

```text
maximum response size
reasonable latency
memory envelope
concurrency limits
```

where meaningful.

---

# E-024.105 — Diagnostics by Construction

E-020 diagnostics should expose for each extension:

```text
identity
version
Extension Point
provider
consumer
Provider Binding
capabilities
runner
isolation class
health
resource use
restart history
state epoch
```

---

# E-024.106 — Capability Routes Are Inspectable

Layer 3 should be able to inspect relationships such as:

```text
Photo Viewer
   ↓ ev.preview.raw
RAW Extension
   ↓ FILE_READ(selected-file)
```

Extension security should be understandable.

---

# E-024.107 — Provider Topology Is Inspectable

Developer/admin tools should be able to answer:

```text
Who provides contract X?
Who consumes it?
Why is provider Y selected?
What capabilities are routed?
What fallback exists?
```

---

# E-024.108 — Extension Dependency Graph

Extensions may depend on other Extension Points/contracts.

Example:

```text
RAW Preview Provider

requires:
    ev.image.decode.raw@1
    ev.graphics.image@3
```

---

# E-024.109 — Depend on Contracts, Not Packages

Preferred:

```text
requires ev.image.decode.raw@1
```

Avoid:

```text
requires BobPlugin42 exactly
```

unless the semantics genuinely require that implementation.

---

# E-024.110 — Hard Dependency Cycles Are Rejected

Impossible activation cycles are detected before activation.

The system must not enter boot/runtime deadlocks because of an extension graph that could have been validated beforehand.

---

# E-024.111 — Lazy Activation

Unused extensions should normally remain stopped.

Example:

```text
ZIP preview extension
```

does not need a permanent daemon merely because it is installed.

---

# E-024.112 — Demand Activation

Conceptually:

```text
consumer requests ev.archive.preview
          ↓
resolve Provider Binding
          ↓
provider started if necessary
          ↓
endpoint routed
```

---

# E-024.113 — No Scan-the-World Startup

Applications should not:

```text
scan filesystem
probe every extension binary
load arbitrary metadata
```

at startup.

Use the provider catalog/binding system.

---

# E-024.114 — Boot-Critical Extensions Are Different

Boot-critical extension composition must be determined before the boot stage that needs it.

Do not dynamically search the Internet or load arbitrary new providers halfway through boot.

---

# E-024.115 — Boot Provider Set Is Generation-Bound

Boot-critical providers should be referenced by the active E-012/E-019 System Generation or relevant Compatibility Cohort.

---

# E-024.116 — Known-Good Boot Fallback

A broken newly selected boot-critical provider must not destroy the previous Known Good provider set.

E-019 rollback semantics apply.

---

# E-024.117 — Provider Resolver Is Not Required to Complete Early Boot

Early boot should have already-resolved provider identities for required components.

A live general Provider Resolver must not become an unavoidable boot root.

---

# E-024.118 — Extension Registry Is Not a God Service

The system may expose a convenient global view of installed extensions.

That view is:

```text
derived
cacheable
reconstructable
```

It does not own the existence or authority of the components it lists.

---

# E-024.119 — Provider Bindings Are the Policy Truth

The meaningful durable decision is:

```text
Contract X at Scope Y
→ Provider Z
```

not an opaque central registry mutation.

---

# E-024.120 — Extension Deprecation

Stable extension contracts require intentional retirement.

Conceptually:

```text
v1 Stable
 ↓
v2 introduced
 ↓
v1 deprecated
 ↓
adapter/support window
 ↓
v1 compatibility capsule if still needed
```

E-015 policy applies.

---

# E-024.121 — Contract Adapters

Where semantics permit:

```text
ev.foo@1
 ↔
adapter
 ↔
ev.foo@2
```

may preserve older extensions.

---

# E-024.122 — Adapters Are Not Eternal

Historical adapters should not accumulate forever in the core platform.

When ecosystem value no longer justifies permanent inclusion:

```text
move to Compatibility Capsule
```

where appropriate.

---

# E-024.123 — Store Is Distribution, Not Authority

The official marketplace may distribute extensions.

But extensions may also come from:

```text
sideload
source build
developer repository
enterprise repository
other permitted channels
```

under E-016/E-019.

---

# E-024.124 — Signature Is Provenance

A signature answers:

> Who published this?

It does not by itself answer:

```text
What can it access?
Where does it run?
Is it healthy?
How much resource may it consume?
```

---

# E-024.125 — Extension Trust Has Multiple Dimensions

Meaningful trust evaluation includes:

```text
provenance
capabilities
isolation
health
resource behavior
contract compatibility
```

Do not reduce this to a signed/unsigned boolean.

---

# E-024.126 — AI Extensions

E-021 AI connectors/tools naturally use E-024 contracts.

An AI tool extension declares:

```text
typed tool interface
capabilities
risk metadata
```

but remains behind the AI Authority Broker.

---

# E-024.127 — AI Extensions Cannot Bypass E-021

Installing an AI connector does not grant it:

```text
unrestricted AI authority
user credentials
all files
```

E-021 containment remains authoritative.

---

# E-024.128 — Foreign Plugin Systems

Plugins used by E-022 foreign applications normally remain inside their Compatibility Realm.

Example:

```text
Windows Photoshop plugin
```

is not automatically an Evrosion system extension.

---

# E-024.129 — Foreign-to-Native Bridge Is Explicit

If a foreign extension should provide a native Evrosion contract:

```text
foreign plugin
 ↓
compatibility adapter
 ↓
explicit Evrosion Extension Point
```

with ordinary capability/isolation rules.

---

# E-024.130 — Extension Development UX

The `ev` tool may eventually provide:

```text
ev extension new
ev extension run
ev extension inspect
ev extension test
ev extension package
```

---

# E-024.131 — Generated Bindings

Extension developers should receive generated:

```text
IDL bindings
manifest templates
capability declarations
test harnesses
documentation
```

where practical.

---

# E-024.132 — Mock Hosts

Because Extension Points are contracts, extensions should be testable against:

```text
mock host
fake resources
fault-injection host
compatibility-version harness
```

without requiring the entire production desktop.

---

# E-024.133 — Stable Conformance Tests

Every Stable Extension Point should have official automated conformance tests.

This follows E-015:

> **Anything called stable must have an automated compatibility test proving that it stayed stable.**

---

# E-024.134 — Conformance Includes Semantics

Conformance should test more than function signatures.

It may include:

```text
lifetime
cancellation
timeout
error behavior
capability behavior
ordering
state migration assumptions
```

where relevant.

---

# E-024.135 — Fault Tests

Extension tests should deliberately inject:

```text
crash
hang
OOM
timeout
malformed response
huge response
protocol violation
version mismatch
```

The consumer/host must remain correct.

---

# E-024.136 — Performance Contract Tests

Extensions on performance-sensitive paths should have measurable resource/latency expectations.

Functional correctness with absurd resource usage is not sufficient.

---

# E-024.137 — Interposition Stress Tests

Filter contracts should test:

```text
chain depth
recursive calls
timeout
cancellation
provider crash
slow provider
fallback behavior
```

to ensure composition cannot deadlock the host.

---

# E-024.138 — Trust-Fusion Tests

Any component eligible for native co-location should be tested both:

```text
isolated
co-located
```

where practical, so semantic behavior does not depend accidentally on shared-process implementation details.

---

# E-024.139 — Extension Point Documentation Is Contract Documentation

Documentation should clearly describe:

```text
what the Extension Point means
what it guarantees
what it does not guarantee
authority model
failure model
resource model
versioning model
```

Not merely list functions.

---

# E-024.140 — Layer 1 UX

Layer 1 should hide almost all architecture.

Possible messages:

> Added weather widget.

> This extension stopped working and was disabled.

> Evrosion switched back to the built-in preview provider.

---

# E-024.141 — Layer 2 UX

Layer 2 may expose:

```text
installed extensions
provider
permissions
resource usage
enable/disable
default provider
health
```

in understandable form.

---

# E-024.142 — Layer 3 UX

Layer 3 may inspect:

```text
extension topology
Provider Bindings
candidate providers
contract versions
capability routes
runner
isolation mode
state epoch
resource contract
lifecycle
failure history
dependency graph
```

and deliberately override policy.

---

# E-024.143 — Extension Provider Override

Layer 3 may manually select a compatible provider even when it is not the recommended choice.

The system explains consequences.

Ownership remains final.

---

# E-024.144 — Extension Point Removal Cannot Be Casual

Removing a Stable Extension Point can strand third-party software.

Such removal must follow E-015 deprecation and compatibility policy.

---

# E-024.145 — Evolution Beats Eternal Core Growth

Historical compatibility may move outward into optional adapters/capsules rather than forcing every old extension contract to remain permanently implemented in the core OS.

---

# E-024.146 — Extension Graph Must Remain Understandable

A user/developer should be able to answer:

```text
What extension changed this behavior?
Which provider is active?
Why was it selected?
What can it access?
What happens if I disable it?
```

If the graph cannot answer those questions, the architecture is becoming too complex.

---

# E-024.147 — Modularity Complexity Must Be Measured

Evrosion should track architectural indicators such as:

```text
number of Stable Extension Points
average dependency depth
maximum filter-chain depth
provider count
compatibility adapters
boot-critical extension count
```

Not as arbitrary limits, but as warnings against uncontrolled complexity growth.

---

# E-024.148 — No Infinite Component Explosion

Creating another service/extension/provider is not automatically the correct architecture.

Sometimes the simpler answer is:

```text
keep functionality inside existing component
```

if it has the same trust, lifecycle, resource and failure boundary.

---

# E-024.149 — Boundary Justification Test

Before creating a new component/Extension Point, ask:

```text
Does it need independent replacement?
Independent failure containment?
Independent security authority?
Independent lifecycle?
Independent scaling/resource policy?
Multiple implementations?
```

If the answer is consistently no:

it may not deserve a separate architectural boundary.

---

# E-024.150 — Modularity Does Not Override Performance

If a modular boundary creates unacceptable measured overhead:

Evrosion may optimize implementation through:

```text
co-location
shared-memory fast path
specialized runner
batching
```

without destroying the logical contract.

---

# E-024.151 — Performance Does Not Override Security Automatically

Conversely:

> “This would be faster in-process”

is not enough to fuse trust domains.

Measured benefit and explicit trust policy are required.

---

# E-024.152 — Control and Data Paths Remain Separate

Extension control may use E-008 IPC.

Bulk/high-rate data should use appropriate:

```text
Memory Objects
shared buffers
GPU Images
specialized queues
```

rather than serializing everything through control RPC.

---

# E-024.153 — Extension Contract Can Define Fast Data Plane

Example:

```text
codec control
→ IPC

video frames
→ GPU Image / Media Buffer
```

Modularity should not imply unnecessary copies.

---

# E-024.154 — Extension Points Preserve E-008 Semantics

Fast-path optimization must preserve:

```text
capability semantics
lifetime
cancellation
deadline
validation
failure
reentrancy
```

The same rule as transport optimization elsewhere.

---

# E-024.155 — Final Provider Resolution Architecture

```text
                    CONSUMER
                       │
                       ↓
                EXTENSION CONTRACT
                       │
                       ↓
                 PROVIDER RESOLVER
                       │
             Candidate Providers
                       │
                       ↓
                 PROVIDER BINDING
                       │
                selected provider
                       │
                       ↓
                 CAPABILITY ROUTE
                       │
                       ↓
                 EXTENSION RUNNER
                       │
          ┌────────────┼────────────┐
          │            │            │
     Native         WebAssembly    Trusted
     Isolated       Component      Native
          │            │          Co-located
          └────────────┼────────────┘
                       ↓
                  EXTENSION JOB
                       │
           ┌───────────┼───────────┐
           │           │           │
       E-009 Caps   E-019 Life   E-023 Resources
                       │
                    E-020
                  Diagnostics
```

---

# E-024.156 — Provider State Architecture

```text
Immutable Package Manifests
          ↓
Reconstructable Provider Catalog
          ↓
Compatible Candidate Set
          ↓
Durable Provider Binding
          ↓
Active Routed Provider
```

Discovery and authority remain separate.

---

# E-024.157 — Isolation Architecture

```text
Extension Contract
       ↓
Isolation Policy
       │
       ├── Native isolated Job
       ├── Sandboxed component runtime
       ├── WebAssembly component
       └── Trusted native co-location
```

Changing isolation strategy should not require changing the logical contract.

---

# E-024.158 — Interposition Architecture

```text
Request
  ↓
Filter A
  ↓
Filter B
  ↓
Provider
```

Each stage has:

```text
explicit order
deadline
resource budget
cancellation
failure semantics
reentrancy contract
causal trace identity
```

---

# E-024.159 — Kernel Microextension Architecture

```text
Verified Microextension
        ↓
Program-Type Declaration
        ↓
Static Verifier
        ↓
Bounded Runtime
        ↓
Approved Stable Helpers
        ↓
Kernel Mechanism
```

No arbitrary kernel access.

---

# E-024.160 — Boot-Critical Architecture

```text
System Generation
       ↓
Pre-resolved Boot Provider Bindings
       ↓
Compatibility Cohort
       ↓
Known-Good Health State
       ↓
Boot
```

General runtime provider discovery is not required to establish the initial trusted system.

---

# E-024 Final Summary

**Extension architecture:** Capability-Routed Extension Fabric

**Core rule:** Extend contracts, not internals

**Extension APIs:** E-015 typed contracts

**Public extension surface:** Deliberately limited

**Maturity:** Internal / Experimental / Preview / Stable

**Extension point explosion control:** Extension Surface Budget

**Provider discovery:** Reconstructable Provider Catalog

**Provider authority:** Durable Provider Binding

**Provider self-promotion:** Forbidden

**Provider replacement:** E-019 transactional

**Provider Resolver:** Policy resolver, not authority source or data path

**Registry:** Reconstructable cache

**Capabilities:** Explicitly routed

**Effective authority:** Intersection of delegation, declaration, policy, layer, invocation scope

**Third-party native default:** Isolated Job/process

**Native in-process code:** Explicit trust fusion

**Automatic co-location:** No

**Co-location basis:** Policy + trust + conformance + measured benefit

**Isolation change:** Lifecycle-managed

**Extension Runners:** First-class

**WebAssembly:** Optional supported runner

**WebAssembly universal requirement:** No

**Kernel modules:** Not normal third-party extensibility

**Kernel-adjacent programmability:** Narrow Verified Microextensions

**Microextension access:** Typed context + stable approved helpers

**Single-provider role:** One selected provider

**Multi-provider role:** Explicit semantics

**Install order semantics:** Forbidden

**Interposition:** Specialized bounded contracts

**Filter chains:** Explicit depth/order/deadline/cancellation/reentrancy/failure

**Dependency cycles:** Validated before activation

**Broken extension:** Contained

**Repeated failure:** Extension Quarantine

**Quarantine:** Disable, not delete

**Lifecycle:** E-019

**Code:** Immutable

**State:** Explicit/versioned/private

**Package:** `.sion`

**Scope:** App / project / user / machine as appropriate

**System-wide registration:** Explicit

**Shell extensions:** Surface + semantics, not internal-memory hooks

**Resources:** E-023 governed

**Diagnostics:** E-020 integrated

**Dependencies:** Prefer contracts over packages

**Activation:** Lazy/on demand

**Boot-critical extensions:** Pre-resolved and health-gated

**Store monopoly:** No

**Stable conformance tests:** Required

**Fault/performance tests:** Required

**Contract adapters:** Supported where semantically valid

**Old adapters:** May move to Compatibility Capsules

**AI extensions:** E-021 brokered

**Foreign plugins:** Stay in E-022 Realms unless explicitly bridged

**Modularity goal:** Independent change without infinite component growth

---

# Governing Principles

> **Extend contracts, never implementation internals.**

> **An Extension Point is a stable typed contract, not an arbitrary hook.**

> **Public Extension Points are scarce long-term promises. Do not extension-point everything.**

> **Discovery is not authority. A provider may advertise a contract without gaining the right to replace the active provider.**

> **Provider Bindings are explicit, durable, scoped, observable, and lifecycle-managed.**

> **A newly installed or malicious provider cannot self-promote into an active system role.**

> **Extensions receive explicitly routed capabilities. They do not inherit host privilege by accident.**

> **Effective extension authority is the intersection of delegation, declared requirements, policy, security layer, and invocation scope.**

> **Untrusted third-party native extensions are isolated by default.**

> **Native in-process co-location is trust-domain fusion. Never pretend otherwise.**

> **Co-location requires a deliberate trust decision and measured benefit, not theoretical performance.**

> **Isolation strategy may change without changing the logical extension contract.**

> **WebAssembly is a useful optional runtime, not a universal religion.**

> **Kernel extensibility remains narrow. Arbitrary third-party kernel modules are not the normal Evrosion extension model.**

> **Kernel-adjacent programmability uses verified, bounded program types and stable helpers instead of raw kernel access.**

> **One logical single-provider role normally has one selected provider.**

> **Multi-provider ordering and aggregation are explicit contract semantics, never installation-order accidents.**

> **Interposition chains are bounded, cancellable, deadline-aware, resource-accounted, and reentrancy-defined.**

> **Hard dependency cycles are rejected before activation.**

> **Every Extension Point defines what happens when the provider fails.**

> **A broken extension should remove or disable the extension, not the host system.**

> **Repeatedly failing extensions may be quarantined and replaced with a known-good provider.**

> **Extension lifecycle uses E-019. There is no second plugin updater.**

> **Extension code is immutable. State is explicit, versioned, and independently managed.**

> **Unused extensions do not run.**

> **Boot-critical composition is pre-resolved and health-gated, never improvised during boot.**

> **Composition beats inheritance.**

> **Extensions depend on contracts where possible, not specific provider packages.**

> **Signing, authority, isolation, health, and resource behavior are separate trust dimensions.**

> **Marketplace distribution never becomes ownership over extensibility.**

> **Stable Extension Points require automated semantic conformance tests.**

> **The provider registry is reconstructable state, never irreplaceable system truth.**

> **The Provider Resolver is not a god service and never sits on the data path.**

> **Modularity exists so pieces can change independently—not so Evrosion can accumulate infinite pieces.**

> **A new component boundary must justify its security, failure, lifecycle, replacement, or scaling value.**

> **Performance may optimize a boundary without erasing the contract.**

> **Security is not sacrificed merely because co-location is faster.**

> **The owner remains the final authority.**

**E-024 — DECIDED AND CLOSED.**

---

# External Design References Consulted During Final Pass

The final adversarial pass considered current component and extension-system patterns from:

- Fuchsia Component Framework — declared component manifests, capability routing, component runners, dynamic composition, and inspectable routing.
- WebAssembly Component Model / WIT — typed imports/exports, explicit worlds, language-neutral composition, and memory/interface boundaries.
- Linux BPF — verifier-controlled programmable behavior, program-type-specific helpers, and the distinction between stable helper contracts and unstable kernel implementation internals.
- Linux livepatch — an example of the synchronization/state complexity involved in modifying live kernel code, reinforcing Evrosion's decision to prefer generation-based kernel updates rather than generic live mutation.

These systems are design references only. E-024 defines Evrosion's own architecture and does not depend on any one of them.
