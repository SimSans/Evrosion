# Evrosion — E-025 Initial Scope

**Status: ARCHITECTURAL DIRECTION DECIDED AND CLOSED**

Evrosion will begin with an:

> **Architecture-Complete, Feature-Minimal Bringup**

The first milestone is not a consumer operating system.

It is the smallest bootable, graphical, capability-native Evrosion system that proves the permanent architecture is real.

The central rule is:

> **Prove the spine before building the body.**

---

# E-025.1 — Purpose of Initial Scope

E-001 through E-024 define where Evrosion may eventually grow.

E-025 defines where implementation starts.

The purpose of the first implementation is not to demonstrate every designed feature.

It is to prove that the major architectural boundaries work together correctly.

---

# E-025.2 — 0.1 Is an Architectural Proof

Evrosion 0.1 should be understood as:

> **A bootable, graphical, capability-native development system running primarily in QEMU/KVM.**

It should prove this chain:

```text
Firmware
   ↓
Bootstrap
   ↓
Evrosion Kernel
   ↓
Initial Root Authority
   ↓
Root Supervisor
   ↓
Userspace Services
   ↓
Capability-Routed IPC
   ↓
Persistent Storage
   ↓
Input / Display
   ↓
Native Application
```

If this works correctly, Evrosion exists as an operating system architecture.

Everything else becomes expansion.

---

# E-025.3 — 0.1 Is Not a Consumer Release

Evrosion 0.1 is not expected to compete with Windows, macOS, Linux distributions, Android, or ChromeOS as a daily-driver consumer product.

It is a development milestone.

It may lack:

```text
Wi-Fi
Bluetooth
audio
hardware acceleration
Windows compatibility
AI
application marketplace
broad driver coverage
```

and still fully succeed.

---

# E-025.4 — Initial Hardware Architecture

Initial architecture:

```text
CPU:
x86-64

Firmware:
UEFI

Primary target:
QEMU/KVM
```

No other hardware architecture may block 0.1.

---

# E-025.5 — Architecture Portable, Implementation Narrow

Evrosion's architecture remains designed for future:

```text
ARM64
RISC-V
other supported platforms
```

But initial implementation intentionally supports only x86-64.

Architecture portability and implementation breadth are different concerns.

---

# E-025.6 — QEMU Is the First Reference Computer

For initial development:

> **QEMU is Evrosion's first reference machine.**

This provides controlled, reproducible hardware for:

```text
CPU topology
RAM
interrupts
timers
block devices
network devices
display
input
boot flow
failure injection
power interruption
```

---

# E-025.7 — QEMU Configuration Is Test Infrastructure

The development tooling should eventually support configurations such as:

```text
ev run --ram 512M
ev run --ram 2G
ev run --cpus 1
ev run --cpus 8
ev run --no-network
```

These are useful for validating E-003, E-005, E-006, E-023 and recovery behavior.

---

# E-025.8 — Initial Host Development Environment

Initial builds may run from a conventional Linux development environment.

Self-hosting is not a requirement for 0.1.

The build should use E-014 principles:

```text
pinned toolchain
declared dependencies
repeatable image generation
offline-capable after bootstrap where practical
```

The host OS is a development environment, not part of Evrosion architecture.

---

# E-025.9 — Do Not Require Self-Hosting Early

Evrosion does not need to compile itself from inside Evrosion before it can be considered real.

Self-hosting is a later maturity milestone.

Requiring it early would add enormous toolchain, shell, package and development-environment scope without proving the core architecture.

---

# E-025.10 — Primary Developer Workflow

The early project should aggressively optimize this loop:

```text
edit
 ↓
ev build
 ↓
ev run
 ↓
Evrosion boots
```

And:

```text
ev debug kernel
```

and:

```text
ev test
```

as soon as each becomes technically possible.

---

# E-025.11 — `ev` Is the Stable Developer Front Door

The exact underlying build engine may evolve.

The developer workflow should remain centered on:

```text
ev bootstrap
ev build
ev run
ev debug
ev test
ev image
ev doctor
```

as defined conceptually in E-014.

---

# E-025.12 — One Command Should Reach QEMU

A normal bringup iteration should not require manually executing:

```text
build kernel
copy binaries
create image
update boot files
launch QEMU
attach debugger
```

one command at a time.

`ev run` should compose those actions.

---

# E-025.13 — Milestones Use Hard Exit Gates

Each milestone must prove specific invariants before the next one becomes the main development target.

Do not declare a milestone complete because:

> It mostly seems to work.

Each milestone has explicit exit tests.

---

# E-025.14 — Milestone Ladder

Initial implementation is divided into:

```text
M0 — Toolchain & Boot Proof
M1 — Kernel Spine
M2 — Capability-Native Userspace
M3 — Persistent Machine
M4 — First Graphical Evrosion
M5 — Native Platform Slice / Evrosion 0.1
M6 — Connected Developer Alpha / post-0.1
```

---

# E-025.15 — M0: Toolchain & Boot Proof

M0 proves:

> We can reliably build, boot, observe and debug Evrosion.

Required capabilities:

```text
ev bootstrap
ev build
ev run
ev debug kernel

x86-64 UEFI boot
QEMU launch
serial output
panic output
symbolized debugging
framebuffer handoff
repeatable image generation
```

---

# E-025.16 — M0 Does Not Need an Operating System Yet

M0 may initially boot only enough code to print:

```text
Evrosion kernel entered.
```

and halt.

That is acceptable.

The point is to make the iteration loop dependable before kernel complexity grows.

---

# E-025.17 — M0 Exit Gate

M0 is complete when a clean development checkout can:

```text
bootstrap toolchain
build image
boot image in QEMU
print deterministic boot diagnostics
enter debugger with symbols
reproduce the same boot path reliably
```

without manual image surgery.

---

# E-025.18 — M1: Kernel Spine

M1 implements the minimum kernel mechanisms needed by the permanent E-002 architecture.

Required mechanisms include:

```text
boot handoff
physical page allocator
virtual address spaces
page mapping
kernel allocation after bootstrap
threads
basic scheduler
exceptions
interrupts
timers
capability/object model
IPC endpoints
wait/wake
process/address-space creation
shared Memory Objects
fault delivery
minimal kernel diagnostics
```

---

# E-025.19 — Kernel Scope Is Mechanism Only

M1 does not put:

```text
filesystem
TCP/IP
GUI
audio
package management
AI
compatibility
user policy
```

inside the kernel.

The kernel remains mechanism-focused from the beginning.

---

# E-025.20 — Simple Scheduler First

Initial scheduling may use a simple correct fair scheduler.

Do not block M1 on:

```text
full deadline scheduling
heterogeneous CPU placement
advanced causal donation
power-aware scheduling
```

The permanent data model should still avoid preventing those later features.

---

# E-025.21 — Single-Core Bringup May Be Temporary

The earliest kernel bringup may run with one CPU.

But the architecture must not assume uniprocessor operation.

SMP should arrive early enough that:

```text
IPC
locking
scheduler
userspace services
graphics
```

do not accidentally hard-code single-core assumptions.

---

# E-025.22 — Memory 0.1

Initial memory support requires:

```text
physical page allocation
virtual mapping
anonymous memory
shared Memory Objects
basic userspace allocation support
```

It does not require:

```text
compression
swap
NUMA
CXL
memory tiering
advanced reclaim policy
```

---

# E-025.23 — M1 Exit Gate

M1 is complete when the kernel can reliably:

```text
create multiple address spaces
run multiple threads
schedule them
map/unmap memory
deliver faults
transfer control through IPC primitives
enforce kernel object capabilities
survive ordinary user-process faults
```

under automated tests.

---

# E-025.24 — M2: Capability-Native Userspace

M2 proves the permanent authority and service model.

Boot flow becomes:

```text
Bootstrap Bundle
      ↓
Root Supervisor
      ↓
isolated Jobs / processes
      ↓
userspace services
```

---

# E-025.25 — Root Supervisor Is the First Important Userspace Program

The first important userspace program is not a shell.

It is:

> **Root Supervisor**

The bootstrap environment gives it initial root capabilities.

It creates and supervises lower-authority components.

---

# E-025.26 — Root Authority Delegation

The Root Supervisor should:

```text
create Job
create process
delegate capability
start service
route service capability
observe service failure
restart service
```

without handing every process universal authority.

---

# E-025.27 — First Capability Test

One of the earliest security tests should be deliberately trivial.

Example:

```text
Process A:
has CAP_TEST_PRINT

Process B:
does not
```

Then:

```text
A invokes print
→ success

B invokes print
→ denied
```

A then delegates or attenuates an appropriate capability to B.

B succeeds only after delegation.

---

# E-025.28 — No "Everything Is Root For Now"

Evrosion must not bootstrap userspace by temporarily giving every process unrestricted authority.

That shortcut would contaminate every early API assumption.

Core rule:

> **No capability means no authority from the beginning.**

---

# E-025.29 — IPC 0.1

The first E-008 implementation only needs:

```text
small synchronous IPC
capability transfer
basic timeout/failure behavior
```

Then add:

```text
Memory Object sharing
```

Async bounded rings can come later when a vertical slice needs them.

---

# E-025.30 — IDL Appears Early

E-015 IDL should be introduced immediately after basic IPC proves stable.

The first contract can be tiny:

```text
ev.test.echo@1
```

Generate:

```text
Rust client
Rust server
wire representation
validation
```

---

# E-025.31 — Avoid Hand-Written Protocol Sprawl

Do not build dozens of custom message formats before the IDL exists.

Temporary hand-written IPC is acceptable only for kernel bringup.

Once services begin multiplying:

use typed contracts.

---

# E-025.32 — First Supervision Failure Test

Example:

```text
Root Supervisor
   ↓
Service A
Service B
```

Deliberately terminate Service B.

Expected result:

```text
Service B fails
Supervisor observes failure
Service B restarts
Service A survives
Kernel survives
```

---

# E-025.33 — M2 Exit Gate

M2 is complete when automated tests prove:

```text
capability denial
capability transfer
capability attenuation
isolated address spaces
service startup
service crash detection
service restart
unrelated-service survival
typed userspace IPC
```

---

# E-025.34 — M3: Persistent Machine

M3 turns Evrosion from a transient demo into a machine with durable state.

It adds:

```text
one block-device path
minimal persistent storage
immutable system content
mutable user/test content
durable operation journal
system generations
Known-Good rollback
```

---

# E-025.35 — One Virtual Block Device

Initial storage should support one virtual block-device family.

VirtIO is a preferred target for the QEMU bringup path.

Do not simultaneously implement:

```text
NVMe
AHCI
USB storage
SD
SATA quirks
RAID
```

---

# E-025.36 — Initial Storage Backend May Be Primitive

The first persistent storage implementation does not need to be the final sophisticated Evrosion filesystem.

It may be intentionally simple.

But it must sit behind final E-010 abstractions.

---

# E-025.37 — Temporary Storage, Permanent Contract

The early backend should expose the same logical ideas that later storage can preserve:

```text
File/Object access
immutable system content
separate mutable state
durable operation boundary
atomic publish
```

The implementation may later be replaced.

The contract should not need to be reinvented.

---

# E-025.38 — Do Not Build the Ultimate Filesystem First

M3 does not need:

```text
deduplication
compression
advanced datasets
snapshots everywhere
quotas
complex multi-device pools
RAID
remote replication
```

before generation rollback works.

---

# E-025.39 — Basic Durable Operations

M3 should prove:

```text
write staging
journal/checkpoint
commit
interrupted operation recovery
```

for at least a minimal subset of storage operations.

---

# E-025.40 — Basic System Generation

M3 introduces the first real E-012/E-019 generation flow.

Conceptually:

```text
Generation A
   ↓
stage B
   ↓
activate B
   ↓
boot B
```

---

# E-025.41 — Known-Good Rollback Is Mandatory

The test must deliberately create a bad generation.

Expected flow:

```text
Generation A = Known Good
      ↓
stage broken B
      ↓
boot B
      ↓
health fails
      ↓
revert to A
```

If that works, one of Evrosion's most important architectural promises is already real.

---

# E-025.42 — Recovery UI May Be Ugly

Initial recovery may be:

```text
serial console
text UI
basic framebuffer menu
```

That is acceptable.

Architecture first.

Polish later.

---

# E-025.43 — Recovery Must Be Real

A recovery screen that merely says:

> Something went wrong.

does not satisfy M3.

It must actually be able to:

```text
identify failed generation
select Known Good
boot it
preserve user/test data
```

---

# E-025.44 — M3 Exit Gate

M3 is complete when tests prove:

```text
persistent read/write
power/interruption-safe durable operation subset
immutable system generation
staged generation activation
health failure detection
automatic/manual Known-Good rollback
preservation of mutable user/test data
```

---

# E-025.45 — M4: First Graphical Evrosion

M4 proves the E-017 application/display model without requiring final GPU support.

Initial stack:

```text
simple display path
software rendering
compositor
surfaces
focus/input routing
text rendering
minimal shell
one graphical app
```

---

# E-025.46 — Do Not Start With a Full Vulkan Driver

A full modern GPU stack is too large to be a prerequisite for the first graphical system.

Initial graphics may use:

```text
firmware/QEMU framebuffer
software renderer
simple compositor
```

---

# E-025.47 — Permanent Surface Boundary

Even with software rendering, applications should still conceptually render into:

> **Application-owned surfaces**

which the compositor presents.

Later GPU acceleration replaces implementation underneath the contract.

---

# E-025.48 — One Input Path

M4 needs only one reliable keyboard/mouse/input path for QEMU.

Do not block on broad HID/USB hardware support.

---

# E-025.49 — Minimal Shell

The first shell only needs enough to prove:

```text
background
window placement
focus
launcher
basic status
```

It does not need:

```text
animations
full customization
themes
widgets
desktop effects
```

---

# E-025.50 — First Graphical Application

Create a deliberately tiny native application such as:

> **Evrosion Hello**

Example UI:

```text
Hello from Evrosion.

[Crash Me]
[Open File]
```

---

# E-025.51 — Crash Test Button

`Crash Me` intentionally terminates/faults the application.

Expected result:

```text
application dies
desktop survives
supervisor records failure
diagnostics exist
application can relaunch
```

---

# E-025.52 — File Grant Test

`Open File` invokes a capability-mediated picker/grant flow.

The application receives access only to the selected file/object.

That proves the user-facing authority model early.

---

# E-025.53 — First App Proves Many Architectures at Once

A tiny graphical app can simultaneously exercise:

```text
E-004 Jobs
E-007 supervision
E-008 IPC
E-009 capabilities
E-010 file access
E-015 APIs
E-016 AppIdentity
E-017 surfaces/input
E-020 diagnostics
E-023 resource accounting
```

This is exactly the kind of vertical slice E-025 should prefer.

---

# E-025.54 — M4 Exit Gate

M4 is complete when Evrosion can:

```text
show shell
accept input
launch graphical native app
route focus
render app surface
open one capability-granted file
kill/crash app
keep shell/system alive
relaunch app
```

---

# E-025.55 — M5: Native Platform Slice

M5 turns the graphical prototype into the first coherent native Evrosion platform.

This is the **Evrosion 0.1 completion milestone**.

---

# E-025.56 — Minimal `.sion`

Initial `.sion` only needs:

```text
manifest
AppIdentity
ELF64 executable
resources
contract requirements
capability declarations
content hashes
```

Advanced package-graph features can arrive later.

---

# E-025.57 — Minimal App Installation

Early installation may simply be:

```text
ev install ./Hello.sion
```

or development deployment.

No marketplace is required.

---

# E-025.58 — AppIdentity Is Real

The launcher and system should know the application by:

```text
AppIdentity
```

not merely executable path.

This establishes E-016 semantics early.

---

# E-025.59 — File Object + Picker Flow

M5 should include a minimal but genuine capability-mediated user file-selection path.

Example:

```text
App requests file
      ↓
Trusted picker
      ↓
user selects file
      ↓
scoped File capability
      ↓
App
```

---

# E-025.60 — Basic Resource Accounting

E-023 does not need full causal QoS yet.

But M5 should expose at least basic Job-level metrics such as:

```text
CPU time
memory use
process count
```

so resource architecture begins with the Job hierarchy.

---

# E-025.61 — Basic Structured Diagnostics

E-020 should initially provide:

```text
structured component identity
basic state
events/logs
crash record
build identity
```

Full tracing and replay can come later.

---

# E-025.62 — Application Crash Record

A crashed Hello.sion should produce a structured record containing at least:

```text
AppIdentity
build ID
fault/exception
thread
basic registers
system generation
```

as available.

---

# E-025.63 — Minimal Application Lifecycle

M5 should prove application lifecycle operations such as:

```text
install
activate
replace/update
rollback
remove
```

for the tiny test application.

---

# E-025.64 — Replaceable Test Provider

E-024 should be proven minimally before 0.1 by one test Extension Point.

Example:

```text
ev.test.provider@1
```

with:

```text
Provider A
Provider B
```

Switch Provider Binding.

Consumer should continue using the contract without knowing the implementation changed.

---

# E-025.65 — No Public Extension Ecosystem Yet

This test proves the architecture.

It does not justify building:

```text
extension store
public SDK ecosystem
thousands of extension points
```

for 0.1.

---

# E-025.66 — Simple Settings / Inspector

M5 should include a small graphical or textual system-inspection utility capable of showing useful state such as:

```text
system generation
running Jobs
services
installed apps
basic resource usage
```

This may be extremely simple.

---

# E-025.67 — Evrosion 0.1 Success Gate

Run:

```text
ev run
```

Evrosion must then:

```text
Boot through UEFI in QEMU
↓
Initialize kernel
↓
Create Root Supervisor
↓
Start isolated userspace services
↓
Route capability-protected IPC
↓
Access persistent storage
↓
Display graphical shell
↓
Accept keyboard/mouse input
↓
Launch Hello.sion
↓
Request a file through trusted picker
↓
Receive only selected file capability
↓
Render application surface
↓
Crash application deliberately
↓
Keep shell and system alive
↓
Record structured failure
↓
Restart application
```

Then separately:

```text
stage broken System Generation
↓
reboot
↓
health check fails
↓
return to Known Good
```

That is Evrosion 0.1.

---

# E-025.68 — 0.1 Ends Here

Networking and physical-machine bringup must **not** be allowed to delay this gate.

This is the most important scope correction.

---

# E-025.69 — M6: Connected Developer Alpha

M6 begins after Evrosion 0.1 succeeds.

This is effectively the next development phase, potentially 0.2/Developer Alpha.

---

# E-025.70 — Minimal Networking

M6 adds one virtual network-device implementation and the smallest usable native networking path.

Possible initial scope:

```text
device
link
IP
DHCP
DNS
TCP/UDP subset sufficient for development/update tests
```

Exact protocol order depends on implementation needs.

---

# E-025.71 — No Full Browser Requirement

Networking does not imply:

> Build Chromium competitor.

Initial network consumers can be:

```text
diagnostic tool
test client
update fetcher
remote development tool
```

---

# E-025.72 — Update Retrieval

Once networking exists, E-019 can retrieve a staged update through E-011 rather than only local test media.

Trust remains separate from transport.

---

# E-025.73 — Remote Developer Tooling

M6 may add secure remote diagnostics/debugging where useful.

This remains development functionality, not mandatory consumer cloud infrastructure.

---

# E-025.74 — First Physical Reference Machine

After the QEMU 0.1 architecture is stable:

choose **one** x86-64 UEFI reference machine.

The first real machine should be selected for simplicity and driver feasibility, not prestige.

---

# E-025.75 — First Physical Hardware Goal

Only require enough real hardware support to achieve:

```text
boot
basic display
keyboard/mouse
storage
network
```

on that one machine.

---

# E-025.76 — Do Not Begin With Universal PC Support

The eventual E-006 architecture supports broad hardware diversity.

Initial implementation should not attempt:

> Every PC.

That would bury the project in drivers before the architecture is proven.

---

# E-025.77 — Modern Discrete GPU Support Is Later

A developer workstation having a modern GPU does not make full accelerated support for that GPU an initial requirement.

Firmware/basic display paths are sufficient for first physical bringup.

Modern GPU enablement is a later subsystem project.

---

# E-025.78 — Audio Comes After Core Native Platform

E-018 remains fully designed.

But audio is not required to prove:

```text
kernel
capabilities
services
storage
graphics
apps
recovery
```

works.

Audio therefore does not block 0.1.

---

# E-025.79 — Networking Comes After Local Architecture

A local-only Evrosion with correct:

```text
capabilities
storage
applications
rollback
graphics
diagnostics
```

is a more important first milestone than a barely coherent OS that can ping.

---

# E-025.80 — Compatibility Comes Later

E-022 implementation does not belong in 0.1.

No requirement for:

```text
Wine
Proton
Linux Personality
Windows Personality
cross-ISA translation
full VMs
.deb support
```

until native Evrosion can correctly install, launch, display, isolate, update and debug its own software.

---

# E-025.81 — AI Comes Later

E-021 implementation does not belong in the bringup critical path.

No requirement for:

```text
AI Authority Broker
Model Router
AI Memory
Web Reader
cloud provider
local model
```

before deterministic native control works.

---

# E-025.82 — AI Must Be Built on the OS, Not Used to Excuse Missing OS

AI can eventually simplify Evrosion.

It should not become a substitute for:

```text
working settings
working file access
working recovery
working service management
```

during initial implementation.

---

# E-025.83 — Marketplace Comes Much Later

M5 needs package installation.

It does not need:

```text
accounts
billing
reviews
developer payments
store discovery
commercial licensing UI
```

Those are product/ecosystem layers.

---

# E-025.84 — Full Accessibility Is Later, But Boundaries Must Not Block It

0.1 does not require a complete accessibility suite.

However:

```text
UI semantics
focus model
text representation
trusted UI architecture
```

should avoid designs that make accessibility impossible to add correctly later.

---

# E-025.85 — Advanced Storage Is Later

0.1 does not require:

```text
compression
dedup
advanced snapshot UI
multi-device pools
storage tiering
complex quotas
```

unless one becomes necessary to prove an invariant.

---

# E-025.86 — Advanced Memory Features Are Later

0.1 does not require:

```text
swap
compression
NUMA optimization
CXL tiering
advanced OOM heuristics
```

but permanent memory abstractions must not prohibit them.

---

# E-025.87 — Advanced Scheduling Is Later

0.1 does not need the full E-023 policy engine.

It should not block future:

```text
causal QoS
deadline admission
heterogeneous placement
thermal coordination
```

---

# E-025.88 — Advanced Power Management Is Later

Initial QEMU development does not require polished:

```text
battery policy
suspend/resume
fan control
thermal optimization
performance modes
```

These enter real-hardware maturity later.

---

# E-025.89 — Legacy BIOS Is Not Initial Scope

UEFI is the first boot path.

Legacy BIOS support may be added later where practical.

It must not delay the first system.

---

# E-025.90 — ARM64 and RISC-V Are Not Initial Scope

Their future support remains architectural.

No implementation work is required before x86-64 Evrosion is coherent.

---

# E-025.91 — Temporary Implementation, Permanent Boundary

This is one of E-025's most important rules.

> **The first implementation of a subsystem may be primitive if it sits behind the permanent contract boundary.**

---

# E-025.92 — Graphics Example

Today:

```text
software renderer
+
framebuffer
```

Later:

```text
Vulkan
GPU acceleration
direct scanout
```

Same logical E-017 surface/display contracts.

---

# E-025.93 — Storage Example

Today:

```text
simple storage backend
```

Later:

```text
advanced datasets
snapshots
compression
multi-device support
```

Same logical E-010 contracts.

---

# E-025.94 — Scheduler Example

Today:

```text
simple fair scheduler
```

Later:

```text
causal scheduling
deadline classes
heterogeneous CPU placement
```

Same E-004 Scheduling Context model.

---

# E-025.95 — Temporary Implementations Must Not Leak

A temporary implementation must not force public contracts to expose implementation-specific behavior.

Bad:

```text
Public API exposes raw framebuffer pointer
because framebuffer is current implementation
```

Preferred:

```text
Public API exposes Surface contract
framebuffer remains implementation detail
```

---

# E-025.96 — Temporary Does Not Mean Unsafe Architecture

Temporary implementations may be:

```text
slow
simple
feature-poor
```

They should not be:

```text
ambient authority everywhere
unversioned protocols everywhere
mutable system files everywhere
unrecoverable updates
```

---

# E-025.97 — Architectural Shortcuts Need Containment

If bringup requires a temporary shortcut:

```text
mark it explicitly
contain it behind an internal boundary
write a removal test/task
prevent it from becoming Stable API
```

Do not normalize accidental prototypes.

---

# E-025.98 — Do Not Implement Architecture Merely Because It Exists

E-001 through E-024 are not a mandatory implementation checklist.

Implement a mechanism when:

```text
a vertical slice needs it
```

or:

```text
delaying it would create expensive architectural debt
```

---

# E-025.99 — Features That Must Arrive Early

Some mechanisms are expensive to retrofit and therefore must be real early:

```text
capability authority
address-space isolation
typed IPC direction
service supervision
durable system generations
rollback
basic build identity
structured diagnostics
```

---

# E-025.100 — Features That Can Arrive Late

Examples:

```text
AI
compatibility
marketplace
advanced GPU
audio
broad drivers
advanced resource policy
advanced filesystem features
```

because their permanent boundaries already exist.

---

# E-025.101 — Clean Repository Structure

The project should use intentional top-level structure from the start.

Conceptually:

```text
/kernel
/platform
/services
/drivers
/libs
/apps
/tools
/idl
/tests
```

Exact names may evolve.

The principle should not.

---

# E-025.102 — No Architecture by Random Folder Accretion

Avoid allowing directories such as:

```text
temp
new2
old
misc
final_final
utils_stuff
```

to become architectural boundaries.

Code organization should mirror subsystem ownership.

---

# E-025.103 — Implementation Growth Requires Structure

As implementation grows, disciplined:

```text
contracts
tests
module ownership
repository boundaries
review
```

remain essential.

Development speed can amplify architecture quality or architecture debt.

---

# E-025.104 — Measure Early

Do not attempt deep optimization before measurement.

But begin measurement early.

Initial useful metrics include:

```text
boot duration
kernel memory footprint
IPC latency
context-switch latency
application launch time
frame latency
basic Job memory use
```

---

# E-025.105 — No Optimization by Architectural Corruption

If a prototype is slow:

measure why.

Do not immediately:

```text
merge trust domains
remove capability checks
move arbitrary services into kernel
```

without evidence.

---

# E-025.106 — Regression Tracking

As soon as practical, CI should track:

```text
boot success
test pass rate
image size
boot time
IPC microbenchmark
memory footprint
app launch
frame timing
```

so performance regressions become visible.

---

# E-025.107 — Fault Injection Arrives Early

Development testing should deliberately exercise:

```text
service crash
process fault
storage interruption
generation failure
malformed IPC
out-of-memory situations
```

as soon as the relevant subsystem exists.

---

# E-025.108 — Power-Loss Testing for Durable Operations

Once M3 storage exists:

automated QEMU tests should terminate/reset the VM at different stages of durable operations and update activation.

Expected result:

```text
old committed state
or
new committed state
```

not corrupt half-state.

---

# E-025.109 — Build Identity From Early Development

Artifacts should carry enough identity to connect:

```text
binary
source revision
build
symbols
system generation
```

before crash debugging becomes complicated.

---

# E-025.110 — 0.1 Security Scope

Required early:

```text
capability enforcement
process isolation
explicit delegation
trusted Root Supervisor
basic package/content integrity
```

Later:

```text
full secret vault
TPM workflows
enterprise policy
advanced Secure Boot UX
```

---

# E-025.111 — 0.1 Recovery Scope

Required:

```text
Known-Good generation
health gate
rollback
basic recovery interface
```

Later:

```text
beautiful Trusted Control UI
advanced repair workflows
network recovery
driver repositories
```

---

# E-025.112 — 0.1 Graphics Scope

Required:

```text
basic display
surface
composition
input
text
shell
```

Later:

```text
GPU acceleration
HDR
VRR
multi-GPU
color management
complex animations
```

---

# E-025.113 — 0.1 Application Scope

Required:

```text
AppIdentity
minimal .sion
launcher
file grant
native GUI app
crash isolation
basic lifecycle
```

Later:

```text
large SDK ecosystem
marketplace
rich app services
compatibility
```

---

# E-025.114 — 0.1 Diagnostics Scope

Required:

```text
serial logs
structured basic events
kernel panic record
app crash record
build IDs
basic state inspection
```

Later:

```text
full causal tracing
replay
advanced profiling
portable Failure Capsules
```

---

# E-025.115 — M6 and Beyond Become User-Value Vertical Slices

After 0.1, development should increasingly organize around useful user outcomes.

Examples:

```text
Connected workstation slice
Real-hardware slice
Media slice
Compatibility slice
AI slice
```

instead of implementing architecture document order.

---

# E-025.116 — Example Connected Workstation Slice

Could include:

```text
networking
richer file management
basic text editor
updates over network
better shell
basic audio
more diagnostics
```

---

# E-025.117 — Example Real-Hardware Slice

Could include:

```text
one reference PC
UEFI boot
storage
display
input
network
power basics
```

then gradually broaden.

---

# E-025.118 — Example Compatibility Slice

Only after native application lifecycle is stable:

```text
first Windows compatibility runtime
or
first Linux personality
```

using E-022 boundaries.

---

# E-025.119 — Example AI Slice

Only after deterministic control paths are mature:

```text
AI Session
Context Broker
one native safe tool
one provider
one quarantine test
```

rather than implementing the entire AI ecosystem at once.

---

# E-025.120 — Initial Scope Anti-Goals

Evrosion 0.1 explicitly does **not** aim to provide:

```text
daily-driver completeness
broad PC hardware support
gaming compatibility
AI assistant
cloud ecosystem
app marketplace
full multimedia
mobile support
enterprise deployment
OEM readiness
perfect UX polish
```

---

# E-025.121 — Scope Creep Test

Before adding a task to the 0.1 critical path, ask:

```text
Does this prove a foundational invariant?

Does this unlock the next required vertical slice?

Would delaying it create expensive architectural debt?
```

If the answer is no:

move it later.

---

# E-025.122 — Milestone Completion Beats Parallel Half-Systems

Prefer:

```text
one complete vertical slice
```

over:

```text
five partially implemented subsystems
```

A working dependency chain teaches more than broad unfinished scaffolding.

---

# E-025.123 — Real Tests Beat Architectural Confidence

A diagram saying:

> services are restartable

does not count.

A test that crashes the service and proves restart:

does.

A diagram saying:

> updates roll back

does not count.

Booting a broken generation and recovering:

does.

---

# E-025.124 — Initial Scope Is a Ratchet

Each milestone should leave the system more useful and more testable.

Do not build milestones that require throwing away the previous one.

---

# E-025.125 — Definition of Success

Evrosion 0.1 succeeds when the following statement is true:

> **A native graphical Evrosion application can boot under the real capability/service/storage/display architecture, receive access only to a user-selected file, crash without killing the system, produce structured diagnostics, restart, and continue running on a system that can roll back from a deliberately broken system generation.**

That single sentence proves an enormous percentage of Evrosion's philosophy.

---

# E-025 Final Milestone Map

```text
M0 — TOOLCHAIN & BOOT
      |
      |  ev build/run/debug
      |  UEFI
      |  QEMU
      |  serial/debug
      ↓
M1 — KERNEL SPINE
      |
      |  memory
      |  threads
      |  scheduler
      |  caps
      |  IPC
      ↓
M2 — CAPABILITY USERSPACE
      |
      |  Root Supervisor
      |  Jobs
      |  services
      |  typed IPC
      |  failure containment
      ↓
M3 — PERSISTENT MACHINE
      |
      |  block device
      |  storage
      |  durable ops
      |  generations
      |  rollback
      ↓
M4 — GRAPHICAL EVROSION
      |
      |  framebuffer
      |  compositor
      |  input
      |  shell
      |  native app
      ↓
M5 — NATIVE PLATFORM SLICE
      |
      |  .sion
      |  AppIdentity
      |  file grants
      |  diagnostics
      |  app lifecycle
      |  provider swap proof
      ↓
   EVROSION 0.1
      ↓
M6 — CONNECTED DEVELOPER ALPHA
      |
      |  networking
      |  update fetch
      |  remote tooling
      |  first real PC
      ↓
   EVROSION 0.2+
```

---

# E-025 Final Summary

**Initial philosophy:** Architecture-complete, feature-minimal

**Primary objective:** Prove permanent architectural spine

**0.1 type:** Development/bringup system

**Initial CPU:** x86-64

**Initial firmware:** UEFI

**Initial reference hardware:** QEMU/KVM

**Initial host build OS:** Conventional Linux acceptable

**Self-hosting required:** No

**Developer frontend:** `ev`

**One-command run loop:** Required early

**Kernel initial scope:** Memory, threads, scheduler, interrupts, caps, IPC, faults

**Kernel filesystem/network/GUI:** No

**Capability enforcement:** Real from early bringup

**Temporary root-everywhere mode:** Forbidden

**Root Supervisor:** Early mandatory userspace component

**Service supervision:** Early

**Typed IDL:** Early

**Storage:** One virtual block path

**Initial storage backend:** May be primitive behind final contracts

**Durable Operations:** Minimal real subset

**System Generations:** Early

**Known-Good rollback:** Mandatory before 0.1 completion

**Graphics:** Software/framebuffer first

**Modern GPU driver:** Not required

**Input:** One QEMU path

**Shell:** Minimal

**First app:** Tiny native graphical test app

**First app crash containment:** Mandatory

**Minimal `.sion`:** Required by M5

**AppIdentity:** Required

**File picker/grant:** Required

**Basic Job accounting:** Required

**Basic structured diagnostics:** Required

**Provider replacement proof:** Minimal test only

**Public extension ecosystem:** Later

**Networking:** Post-0.1

**First real machine:** Post-0.1

**Audio:** Later

**Compatibility:** Later

**AI:** Later

**Marketplace:** Later

**ARM64/RISC-V:** Later

**Legacy BIOS:** Later

**Universal hardware coverage:** Later

**Advanced filesystem/memory/scheduler/power features:** Later

**Temporary implementation rule:** Primitive implementation allowed; permanent boundary preserved

**Optimization rule:** Measure first

**Milestone rule:** Explicit exit gates

**0.1 success:** Native graphical app + scoped file access + crash containment + diagnostics + restart + Known-Good rollback

---

# Governing Principles

> **Prove the spine before building the body.**

> **Architecture-complete does not mean feature-complete.**

> **The first Evrosion is a development system, not a consumer-product checklist.**

> **QEMU is the first reference computer.**

> **x86-64 UEFI is the only initial hardware architecture.**

> **A one-command build/run/debug loop is part of the product for the developer.**

> **Every milestone has explicit exit tests.**

> **Capabilities, IPC, isolation, supervision, durable state, rollback, and diagnostics become real early because they are expensive to retrofit.**

> **No capability means no authority from the beginning.**

> **Do not create dozens of hand-written service protocols before the IDL exists.**

> **Recovery must become real before the system becomes complicated enough that recovery is desperately needed.**

> **The first graphical implementation may be software-rendered. The public architecture must still be the permanent surface architecture.**

> **The first storage implementation may be primitive. The public architecture must still be the permanent storage contract.**

> **The first scheduler may be simple. The surrounding architecture must not prohibit the final scheduling model.**

> **Temporary implementations are acceptable. Temporary architectural boundaries are not.**

> **Do not implement a subsystem merely because its architecture has been designed. Implement it when a vertical slice requires it.**

> **No compatibility ecosystem before native applications work correctly.**

> **No AI dependency before deterministic system control works correctly.**

> **No universal hardware campaign before one virtual target and one physical target work correctly.**

> **Networking and first physical-PC bringup happen after the 0.1 architecture proof and cannot delay it.**

> **No optimization without measurement.**

> **Do not destroy security or modularity to fix an unmeasured performance problem.**

> **One complete vertical slice is worth more than several half-built subsystems.**

> **Architecture claims become real only when failure tests prove them.**

> **Each milestone must leave a foundation for the next rather than becoming disposable prototype code.**

> **Evrosion 0.1 succeeds when one native graphical application can run, access an explicitly granted file, crash without killing the system, produce diagnostics, restart, and survive a system-generation rollback test.**

**E-025 — DECIDED AND CLOSED.**
