# Evrosion — E-022 Compatibility Architecture

**Status: ARCHITECTURAL DIRECTION DECIDED AND CLOSED**

Evrosion will use a:

> **Layered Compatibility Fabric with Foreign OS Personalities, Reproducible Compatibility Realms, Semantic Host Adapters, Independent ISA Translation, and VM Fallback**

Compatibility exists to run foreign software without allowing foreign operating-system assumptions to dictate Evrosion's native architecture.

The central rule is:

> **Compatibility adapts foreign software to Evrosion. Evrosion does not adapt itself into the foreign operating system.**

---

# E-022.1 — Native Software Never Pays for Compatibility

If the user runs no foreign software, compatibility should impose effectively no runtime cost.

Evrosion should not permanently run:

- Windows compatibility daemons
- Linux container services
- Foreign kernels
- Cross-ISA translators
- Foreign desktop infrastructure
- Compatibility package managers

merely because such software might be used someday.

Compatibility components activate on demand.

---

# E-022.2 — Compatibility Is Layered

A foreign application's execution environment may contain several independent compatibility layers.

Conceptually:

```text
Application
    ↓
Foreign OS Personality
    ↓
Optional ISA Translation
    ↓
Semantic Host Adapters
    ↓
Native Evrosion Services
```

A full virtual machine is the final fallback when translation cannot provide correct semantics.

---

# E-022.3 — OS Personality and CPU ISA Are Separate Axes

Evrosion must never fuse:

> Windows compatibility

with:

> x86 emulation.

They solve different problems.

Examples:

```text
Windows x86-64 application on x86-64 Evrosion
→ Windows Personality

Windows x86-64 application on ARM64 Evrosion
→ Windows Personality + x86-64→ARM64 translation

Linux ARM64 application on ARM64 Evrosion
→ Linux Personality

Linux x86-64 application on ARM64 Evrosion
→ Linux Personality + x86-64→ARM64 translation
```

Principle:

> **Foreign OS semantics and foreign CPU instructions are independent problems.**

---

# E-022.4 — Application Broker Chooses the Execution Path

E-016's Application Broker identifies:

```text
Executable format
Target ISA
Required OS personality
Runtime requirements
Compatibility profile
Known constraints
```

It then selects the cheapest correct execution path.

---

# E-022.5 — Execution Ladder

Preferred order:

```text
Native Evrosion
      ↓ if foreign
Foreign Personality
      ↓ if ISA differs
ISA Translation
      ↓ if semantics still impossible
Full Virtual Machine
      ↓
Unsupported
```

The system should not choose a heavier path when a lighter correct path exists.

---

# E-022.6 — Native Is Preferred When Equivalent

If both exist:

```text
Native Evrosion version
Foreign compatibility version
```

the native version should normally be preferred unless the user chooses otherwise.

Compatibility is a bridge.

Native Evrosion remains the intended destination.

---

# E-022.7 — Evrosion Kernel Remains Evrosion

The kernel must not gradually accumulate:

```text
Linux syscall policy
Windows NT policy
Darwin/Mach policy
Android-specific behavior
foreign filesystem semantics
```

That would corrupt E-002.

---

# E-022.8 — Generic Foreign Execution Mechanism

The kernel may expose generic mechanisms needed to support foreign execution.

Conceptually:

```text
Foreign Thread
    ↓
Foreign trap / exception
    ↓
Kernel
    ↓
Authorized Compatibility Supervisor
```

The kernel understands:

> This foreign execution context belongs to supervisor X.

It need not understand the foreign operating system itself.

---

# E-022.9 — Foreign Policy Lives in Userspace

Linux, Windows, Darwin and future personalities belong primarily in userspace compatibility components.

This keeps:

- Kernel complexity low
- Security boundaries clean
- Foreign semantics replaceable
- Compatibility independently updateable

---

# E-022.10 — Compatibility Reproduces Reality

Compatibility must implement foreign behavior as software expects it.

This includes:

- Historical quirks
- Odd edge cases
- Legacy semantics
- Broken-but-relied-upon behavior

Principle:

> **Compatibility implements the foreign contract as it exists, not as Evrosion wishes it had been designed.**

---

# E-022.11 — Foreign Weirdness Must Stay Contained

If Windows or Linux has ugly historical behavior:

Evrosion compatibility may reproduce it.

Native Evrosion APIs do not inherit it.

Compatibility gets dirty.

The native architecture stays clean.

---

# E-022.12 — Compatibility Personality

A:

> **Compatibility Personality**

represents the foreign operating-system contract.

Possible personalities include:

```text
Linux Personality
Windows Personality
Darwin Personality
Future personalities
```

---

# E-022.13 — Personality Responsibilities

A foreign personality may implement:

```text
Binary loading
ABI behavior
System-call semantics
Process/thread semantics
Signals/exceptions
Foreign object namespaces
Filesystem expectations
Socket/network semantics
Foreign IPC
Synchronization primitives
Environment conventions
```

It maps these concepts onto Evrosion mechanisms.

---

# E-022.14 — Linux Personality

Evrosion should eventually provide a native:

> **Linux Personality**

capable of running unmodified Linux userspace binaries without requiring a Linux VM where feasible.

---

# E-022.15 — Linux Compatibility Surface

The Linux Personality may implement:

```text
Linux syscalls
Signals
Futexes
epoll
process/thread semantics
Linux sockets
ioctls
permissions
namespaces
Linux object semantics
/proc behavior
/sys behavior
/dev behavior
```

Coverage evolves over time.

---

# E-022.16 — Linux Compatibility VFS

Linux filesystem semantics should be represented through a Linux-specific Compatibility VFS.

Conceptually:

```text
Linux Application
      ↓
Linux Compatibility VFS
      ↓
Evrosion storage/resources
```

This avoids polluting E-010 with Linux-specific behavior.

---

# E-022.17 — Synthetic Linux Filesystems

The compatibility VFS may synthesize:

```text
/proc
/sys
/dev
```

and other Linux-specific pseudo-filesystems.

These are compatibility views.

They do not become native Evrosion filesystem concepts.

---

# E-022.18 — Linux Runtime Environment Is Separate From Linux Personality

The Linux Personality implements the OS contract.

Distro/runtime environments provide:

```text
glibc
musl
libraries
/etc
package state
distribution-specific files
```

These are separate concerns.

---

# E-022.19 — Multiple Linux Environments

One Linux Personality may support multiple environments:

```text
Debian
Ubuntu
Alpine
Minimal Linux runtime
Custom enterprise runtime
```

without implementing Linux itself repeatedly.

---

# E-022.20 — Linux Packages Stay Inside Linux Realms

Packages such as:

```text
.deb
.rpm
.apk
```

must not install into native Evrosion.

Instead:

```text
foreign package
      ↓
foreign package manager
      ↓
Compatibility Realm
```

---

# E-022.21 — Maintainer Scripts Are Contained

Foreign package scripts execute within their compatibility environment.

They do not receive arbitrary host authority.

A Linux installer cannot modify native Evrosion simply because it assumes Linux root access.

---

# E-022.22 — Windows Is a High-Priority Compatibility Target

Windows compatibility is strategically important for:

- Games
- Creative software
- Business software
- Legacy applications
- Existing commercial ecosystems

Windows should therefore receive early practical attention.

---

# E-022.23 — Initial Windows Bootstrap

The initial practical implementation may build heavily on:

- Wine
- Proton
- DXVK
- VKD3D-style systems
- Existing open compatibility technologies

Reusing mature compatibility work is preferable to rewriting everything for ego.

---

# E-022.24 — Linux Is Not the Permanent Windows Substrate

Initial implementation may contain Linux-oriented compatibility technology.

That does not mean permanent architecture becomes:

```text
Windows
 ↓
Wine
 ↓
Linux compatibility
 ↓
Evrosion
```

forever.

---

# E-022.25 — Direct Windows Host Adapter Path

Long-term architecture must permit:

```text
PE / NT / Win32
      ↓
Windows Personality
      ↓
Evrosion Host Adapters
      ↓
Native Evrosion
```

without requiring a Linux compatibility layer beneath it.

Layers should disappear when they cease providing value.

---

# E-022.26 — PE Is a First-Class Recognized Format

The Application Broker should understand PE executables directly.

Example:

```text
foo.exe

format = PE
ISA = x86-64
personality = Windows
```

The user should not need to manually invoke a Wine command.

---

# E-022.27 — Foreign Applications Receive Evrosion AppIdentity

A Windows or Linux application becomes a normal E-016:

> **Evrosion AppIdentity**

Evrosion can therefore track:

```text
Application name
Version
Runtime
Compatibility Realm
Capabilities
Resources
Lifecycle
Background activity
Resource use
Compatibility profile
```

---

# E-022.28 — Foreign Applications Are First-Class Citizens

The launcher should show:

> Photoshop

not:

> wine64 /prefix/foo/C:/Program Files/...

Compatibility details are available for advanced inspection.

They should not dominate ordinary UX.

---

# E-022.29 — Compatibility Realm

Each foreign application or intentionally related suite runs inside a:

> **Compatibility Realm**

The Realm contains mutable foreign-world state.

---

# E-022.30 — Windows Realm

A Windows Realm may contain:

```text
C:\
Registry
AppData
COM state
Windows services
DLL overrides
named objects
runtime configuration
installer state
```

---

# E-022.31 — Linux Realm

A Linux Realm may contain:

```text
root filesystem overlay
/etc
/var
package-manager state
namespace state
runtime configuration
foreign service state
```

---

# E-022.32 — Runtime and Realm Are Different

Compatibility Runtime:

```text
immutable
shared
versioned
```

Compatibility Realm:

```text
mutable
application-specific
isolated
```

This separation is fundamental.

---

# E-022.33 — Copy-on-Write Realm Storage

A compatibility environment should use shared immutable base content plus private CoW state.

Conceptually:

```text
Shared Windows Runtime
       +
Application Realm Overlay
```

or:

```text
Shared Linux Runtime
       +
Application Realm Overlay
```

This reduces disk usage while preserving isolation.

---

# E-022.34 — No Global Wine Prefix

The default should not be:

```text
one global mutable Windows environment
```

for every Windows application.

Instead:

```text
Application A Realm
Application B Realm
Application C Realm
```

---

# E-022.35 — Shared Realms Are Deliberate

Some software suites legitimately depend on shared state.

Example:

```text
Creative Suite Realm
├── Application A
├── Application B
└── Shared components
```

A shared Realm requires deliberate declaration or user choice.

---

# E-022.36 — Shared Realm Security

Applications sharing a Realm may interact through the foreign environment.

Therefore:

> **Realm sharing is a security boundary decision, not merely a storage optimization.**

Apps inside the same Realm may potentially access shared:

- Registry state
- Files
- Foreign IPC
- Foreign services
- Named objects

The UI and manifest model must represent this honestly.

---

# E-022.37 — Shared Realm Does Not Merge Evrosion Capabilities

Even when two apps share a Realm:

Their host-side Evrosion capabilities remain separate unless deliberately shared.

Foreign interaction does not automatically merge native authority.

---

# E-022.38 — Compatibility Translates Semantics, Never Privilege

If a foreign program expects access to:

```text
C:\Users\User\Documents
```

that expectation alone grants nothing.

The foreign path may expose only resources authorized by Evrosion.

Principle:

> **Compatibility translates semantics. It does not translate foreign assumptions into host authority.**

---

# E-022.39 — Host Files Enter Through Capabilities

If the user grants:

```text
report.docx
```

to a Windows app, compatibility may expose it as:

```text
Z:\Documents\report.docx
```

or another suitable foreign representation.

Underlying authority remains the Evrosion File capability.

---

# E-022.40 — Foreign Filesystem Views Are Synthetic

A Windows app may believe it has:

```text
C:
D:
Z:
```

A Linux app may believe it has:

```text
/
home
proc
sys
dev
```

These are compatibility views.

They do not redefine host storage architecture.

---

# E-022.41 — Device Access Is Brokered

Foreign software should normally receive synthetic or translated representations of devices.

Example:

```text
Windows gamepad API
     ↓
Evrosion input device
```

or:

```text
Linux /dev/video0
     ↓
Evrosion camera capability
```

---

# E-022.42 — No Ambient Device Authority

A foreign application's expectation that:

```text
/dev/*
```

or:

```text
Windows device namespace
```

exists does not give it unrestricted access to hardware.

Native E-009 capabilities still determine actual authority.

---

# E-022.43 — Foreign Kernel Drivers Never Enter Evrosion Kernel

Absolute rule:

```text
Windows .sys
Linux .ko
```

must never simply become Evrosion kernel modules.

Doing so would destroy the kernel/security architecture.

---

# E-022.44 — Kernel-Driver Dependencies

Software requiring a foreign kernel driver may use:

```text
Userspace compatibility replacement
Synthetic/paravirtual device
Full VM
Unsupported
```

depending on what is technically possible.

---

# E-022.45 — Anti-Cheat and Deep DRM

Some applications depend on:

- Windows kernel anti-cheat
- Kernel DRM
- Foreign privileged drivers
- Hardware-specific assumptions

Evrosion must be honest.

Possible outcomes:

```text
Compatibility works
VM required
Unsupported
```

Security architecture is not sacrificed merely to increase compatibility statistics.

---

# E-022.46 — Native Graphics Fast Path

Foreign graphics APIs should reach E-017 as early as possible.

Example:

```text
Direct3D 11
   ↓
D3D→Vulkan translation
   ↓
Native Vulkan
   ↓
E-017
```

---

# E-022.47 — Do Not Emulate More Than Necessary

If a foreign high-level API can map efficiently onto a native Evrosion subsystem:

translate there.

Do not emulate an entire foreign subsystem beneath it unnecessarily.

---

# E-022.48 — Foreign Audio Fast Path

Conceptually:

```text
WASAPI / XAudio
      ↓
Windows Media Adapter
      ↓
E-018
```

or:

```text
Linux audio API
      ↓
Linux Media Adapter
      ↓
E-018
```

---

# E-022.49 — Foreign Networking Fast Path

Conceptually:

```text
Winsock
 ↓
Windows Network Adapter
 ↓
E-011
```

or:

```text
Linux socket()
 ↓
Linux Personality
 ↓
E-011
```

---

# E-022.50 — Native Display Integration

Foreign windows should become E-017 surfaces where practical.

Conceptually:

```text
Win32 Window
      ↓
Compatibility Window Adapter
      ↓
E-017 Surface
```

---

# E-022.51 — Native Input Integration

Evrosion input is translated into foreign input semantics.

Compatibility does not need to own the physical input stack.

---

# E-022.52 — Native Clipboard/Data Transfer

Foreign clipboard and drag-and-drop operations should integrate with Evrosion's native data-transfer capabilities.

Compatibility should not bypass privacy boundaries.

---

# E-022.53 — Highest-Level Translation Principle

Governing rule:

> **Translate at the highest semantic level available. Emulate instructions only where necessary.**

Examples:

```text
Vulkan call
→ ABI thunk to native Vulkan
```

is generally preferable to:

```text
execute an entire foreign Vulkan library through ISA translation
```

when equivalent behavior can be preserved.

---

# E-022.54 — ISA Translation Service

Cross-architecture execution is provided by a separate:

> **ISA Translation Runtime**

Possible conversions include:

```text
x86-64 → ARM64
x86-32 → ARM64
future combinations
```

---

# E-022.55 — Translator Implementation Is Replaceable

The architecture does not mandate:

```text
JIT
AOT
interpretation
hybrid translation
```

Any of these may be used where appropriate.

---

# E-022.56 — Translation Cache

Translated code may be cached according to:

```text
Foreign code hash
Translator version
Foreign ISA
Host ISA
CPU feature set
Runtime profile
```

The cache is reconstructable and disposable.

---

# E-022.57 — Translation Cache Is Not User Data

Corrupt translation cache:

```text
delete
rebuild
```

No user-created content should depend on it.

---

# E-022.58 — JIT and Self-Modifying Code

Foreign applications may generate or modify executable code.

Compatibility must support legitimate JIT/self-modifying workloads without granting unrestricted executable-memory authority.

---

# E-022.59 — W^X Remains the Host Security Model

Where possible, foreign JITs should obey a model such as:

```text
Writable
→ finalize
→ Executable
```

rather than arbitrary permanent:

```text
WRITE + EXECUTE
```

memory.

Compatibility may emulate foreign expectations through controlled transitions.

---

# E-022.60 — Translator Owns JIT Mediation

Self-modifying foreign code should be tracked through the ISA translator/runtime.

Changes invalidate affected translated blocks.

The translator rebuilds only what is necessary.

---

# E-022.61 — JIT Cannot Escape Capability Boundaries

Generating executable code does not create new Evrosion authority.

The generated code retains the capabilities of its owning Job/process.

---

# E-022.62 — Windows NT Objects

Windows compatibility must reproduce important NT object semantics where required.

Possible foreign concepts include:

```text
Events
Mutexes
Semaphores
Sections
Named pipes
Shared memory
Timers
Object namespaces
Handles
```

---

# E-022.63 — NT Object Layer Belongs in Windows Personality

Evrosion should not add Windows NT object semantics to the native kernel merely because Windows software uses them.

Implement them through compatibility objects backed by generic native primitives.

---

# E-022.64 — Synchronization Fast Paths

High-frequency foreign synchronization must not require expensive heavyweight round trips for every operation.

Where correctness allows:

```text
Foreign synchronization
      ↓
shared memory / atomics / wait primitives
      ↓
native fast path
```

The compatibility personality handles semantics while using efficient native mechanisms.

---

# E-022.65 — Fidelity Before Unsafe Optimization

Fast paths must preserve:

- Wake semantics
- Ordering
- Timeout semantics
- Handle lifetime
- Cancellation
- Foreign error behavior

Performance is important.

Incorrect synchronization is worse.

---

# E-022.66 — Foreign Installers

Foreign installers execute inside a staged Compatibility Realm.

Example:

```text
Installer
   ↓
Temporary/Staged Realm
   ↓
Files
Registry
Services
Configuration
   ↓
Health / launch test
   ↓
Commit
```

---

# E-022.67 — Installers Do Not Mutate Native Evrosion

A Windows installer may believe it changed:

```text
C:\Windows
Registry
Windows Services
```

but those changes stay inside its Realm/runtime environment.

---

# E-022.68 — Installer Capture

The compatibility system may record resulting foreign state.

This can create:

```text
AppIdentity
Realm
Compatibility profile
Launcher entry
Dependencies
```

from a legacy installer workflow.

---

# E-022.69 — Realm Snapshots

Before high-risk installer/self-updater operations, Evrosion should snapshot or checkpoint the Realm where practical.

Then:

```text
Update succeeds
→ commit

Update breaks application
→ restore Realm
```

---

# E-022.70 — Foreign Self-Updaters

Foreign applications may continue using their own self-updaters.

Those self-updaters modify compatibility state.

They do not gain authority over native Evrosion package state.

---

# E-022.71 — Self-Updater Containment

A foreign updater sees what its Realm allows.

It cannot automatically overwrite:

- Evrosion system components
- Other application Realms
- Native apps
- Other users' files

---

# E-022.72 — Compatibility Profiles

Applications may require versioned:

> **Compatibility Profiles**

A profile may define:

```text
Foreign OS version identity
Compatibility runtime
Graphics backend
Audio backend
Synchronization mode
ISA translator
Environment settings
DLL/library overrides
Known workarounds
```

---

# E-022.73 — Quirks Are Per-Application Data

Bad:

```text
global kernel special-case for Game X
```

Good:

```text
Game X Compatibility Profile
    ↓
local workaround
```

Principle:

> **Compatibility quirks are scoped data, not permanent global architecture.**

---

# E-022.74 — Profiles Are Versioned

Compatibility profile changes should be tracked like other managed software.

If:

```text
Profile 18 works
Profile 19 breaks app
```

Evrosion can restore Profile 18.

---

# E-022.75 — Compatibility Cohorts

A working application environment may require a specific combination.

Example:

```text
Game Compatibility Cohort
├── Windows Runtime 12
├── DXVK 8
├── ISA Translator 4
└── Compatibility Profile 27
```

E-019 may update/rollback the cohort coherently.

---

# E-022.76 — Compatibility Is Reproducible

Evrosion should record enough state to know exactly which compatibility stack was used.

Potential identity:

```text
App version
Realm generation
Personality version
Runtime version
Graphics translator
ISA translator
Compatibility profile
System generation
```

---

# E-022.77 — Compatibility Realms Are Lifecycle-Managed

Compatibility Realms integrate with:

- E-010 snapshots
- E-016 applications
- E-019 lifecycle
- E-020 diagnostics

Realm state is not random hidden filesystem garbage.

---

# E-022.78 — Foreign Background Services

Foreign applications may install background services.

They remain:

```text
Compatibility processes
```

under Evrosion Jobs/supervision.

They do not automatically become trusted native E-007 services.

---

# E-022.79 — Foreign Service Authority

A Windows/Linux service inside a Realm receives only the host capabilities granted to that Realm/application.

“Running as SYSTEM” or “root” inside the foreign environment does not mean:

> Evrosion system authority.

---

# E-022.80 — Foreign Root Is Virtual Authority

Compatibility may emulate:

```text
root
Administrator
SYSTEM
```

inside a Realm.

These identities are foreign-environment concepts.

They do not automatically map to Evrosion owner/root authority.

---

# E-022.81 — Lazy Activation

Compatibility services activate only when needed.

Examples:

```text
No Windows apps running
→ Windows runtime mostly inactive

No Linux apps running
→ Linux personality inactive

No cross-ISA app running
→ translator inactive
```

---

# E-022.82 — 32-Bit Foreign Software

Evrosion remains a 64-bit native OS.

32-bit support exists through compatibility.

Examples:

```text
Win32 application
→ 32-bit Windows compatibility
→ 64-bit Evrosion host
```

```text
ELF32
→ 32-bit Linux ABI personality
→ 64-bit Evrosion host
```

---

# E-022.83 — No Native 32-Bit Kernel Requirement

Supporting old software does not require maintaining a native 32-bit Evrosion kernel architecture.

This keeps the core smaller.

---

# E-022.84 — VM Is the Final Fidelity Boundary

A full VM is appropriate when software fundamentally requires:

- Foreign kernel
- Foreign kernel drivers
- Unsupported privileged semantics
- Extremely high fidelity
- Full foreign OS environment
- Difficult enterprise stacks
- Development/testing

---

# E-022.85 — VM Is Not Default Compatibility

VMs carry significant overhead:

- Memory
- Storage
- Boot time
- Background services
- Device virtualization
- Guest maintenance

Use them only when lighter translation cannot correctly satisfy requirements.

---

# E-022.86 — Explicit VM Escalation Boundary

Evrosion should define a clear decision:

> Translation cannot safely/correctly satisfy this application's required semantics.

Then VM becomes the next execution strategy.

---

# E-022.87 — Translation-to-VM Criteria

Possible reasons include:

```text
Required foreign kernel driver
Required kernel anti-cheat
Required unsupported syscall/kernel semantic
Unsupported device model
Foreign privileged service dependency
Unacceptable compatibility divergence
Application vendor explicitly requires full OS
```

---

# E-022.88 — Do Not Silently Switch to a VM

Execution strategy changes:

- Performance
- Storage
- Privacy
- Filesystem semantics
- Networking
- Licensing
- Security boundary

Therefore Evrosion must not silently switch.

The user or policy receives a meaningful explanation.

---

# E-022.89 — VM Strategy Is Part of AppIdentity

If an application runs in:

```text
Windows VM
```

that becomes part of its configured execution profile.

It remains reproducible and inspectable.

---

# E-022.90 — Integrated VM Presentation

Where technically useful, guest applications may integrate with Evrosion.

Examples:

```text
Guest window
→ E-017 Surface

Guest audio
→ E-018

Guest clipboard
→ Native data-transfer service

Guest shared directory
→ Capability-backed host share
```

The VM security boundary remains real.

---

# E-022.91 — VM Shared Resources Are Explicit

A VM does not automatically see the host filesystem or devices.

Shared:

- folders
- microphones
- cameras
- clipboard
- networking
- USB devices

remain explicit capabilities/policy.

---

# E-022.92 — macOS/Darwin Compatibility

Evrosion architecture should permit future Darwin/macOS personality work.

Potential requirements include:

```text
Mach-O loading
Mach/Darwin semantics
dyld behavior
Objective-C runtime
Framework implementations
Graphics/UI adapters
```

---

# E-022.93 — macOS Is Later / Optional

macOS compatibility is a major undertaking.

It is not required for initial Evrosion success.

The architecture should support it without committing initial engineering resources.

---

# E-022.94 — Apple Licensing Boundary

Evrosion must not depend on redistributing proprietary Apple system components without legal permission.

Compatibility should use:

- Independently implemented components
- Open components
- User-supplied components where legally permitted

according to final legal review.

---

# E-022.95 — Android Future Compatibility

A future Android environment may naturally build from:

```text
Linux Personality
+
Android userspace/runtime
+
Android-specific host adapters
```

No architectural commitment is required now.

The important requirement is that E-022 does not prevent it.

---

# E-022.96 — Differential Compatibility Testing

Compatibility correctness should be tested against reference systems.

Example:

```text
Test Program
    ↓
Reference Windows
```

and:

```text
Same Test Program
    ↓
Evrosion Windows Personality
```

Compare externally observable results.

---

# E-022.97 — Linux Reference Testing

Likewise:

```text
same Linux userspace test
```

runs on:

```text
reference Linux
Evrosion Linux Personality
```

Differences reveal compatibility mismatches.

---

# E-022.98 — Foreign Behavior Is the Reference

When written documentation is ambiguous:

> **Observed reference-system behavior is part of the compatibility specification.**

This does not mean blindly copying security bugs.

It means reproducing externally visible contracts required by legitimate applications.

---

# E-022.99 — Compatibility Quality Is Measurable

Development tooling should track:

```text
API coverage
Syscall coverage
Test pass rate
Known stub hits
Unimplemented calls
Compatibility regressions
Performance overhead
```

Not:

> “Seems pretty compatible.”

---

# E-022.100 — Performance Is Measured Too

Compatibility benchmarks should measure:

```text
CPU translation overhead
Graphics translation overhead
Startup latency
Memory overhead
Realm storage
IPC/syscall overhead
Synchronization cost
Native-adapter coverage
```

---

# E-022.101 — Compatibility Failure Capsules

E-020 Failure Capsules should include compatibility-specific information.

Potential contents:

```text
AppIdentity
Personality
Compatibility Realm
Runtime version
Realm generation
Compatibility Profile
ISA Translator
Graphics Translator
Failed foreign API/syscall
Foreign exception state
Relevant trace
System generation
```

---

# E-022.102 — Reproduction

Development tooling may eventually support:

```text
ev compat reproduce <failure-capsule>
```

to reconstruct an equivalent compatibility environment where possible.

---

# E-022.103 — Compatibility Health State

Application Broker may expose factual status such as:

```text
Compatible
Compatible with known limitation
Requires Compatibility Profile
Requires full VM
Unsupported
```

The state should describe concrete limitations.

---

# E-022.104 — Honest Compatibility Messages

Useful:

> Microphone access is not currently supported by this runtime.

Not useful:

> Compatibility issue occurred.

Layer 1 gets clear language.

Layer 3 gets technical detail.

---

# E-022.105 — Native Migration

If a native Evrosion release of a previously foreign application becomes available:

Evrosion may offer migration.

Potentially:

```text
Foreign AppIdentity
      ↓
Vendor-defined migration
      ↓
Native AppIdentity
```

User data remains under user control.

---

# E-022.106 — Native Migration Is Optional

Do not silently replace foreign software simply because a native version exists.

The user may depend on:

- Plugins
- Version behavior
- Compatibility setup
- Different licensing

Migration remains deliberate.

---

# E-022.107 — No Compatibility Lock-In

Compatibility runtimes should remain replaceable.

An application should not permanently depend on one implementation merely because that was the first one installed.

Its profile defines requirements.

The resolver selects compatible implementations.

---

# E-022.108 — Compatibility Components Use E-019

Personality runtimes, translators, compatibility profiles and environment bases all use the standard Lifecycle Engine.

They may be:

```text
Installed
Updated
Rolled back
Pinned
Removed
```

---

# E-022.109 — No Separate Compatibility Updater

Do not invent:

```text
Wine updater
Linux-runtime updater
translator updater
profile updater
```

as independent unmanaged mechanisms.

E-019 is authoritative.

---

# E-022.110 — Compatibility Uses E-020 Diagnostics

Foreign software should remain observable through normal Evrosion tooling.

Examples:

```text
ev inspect app
ev trace
ev crash
ev profile
```

Compatibility-specific detail is added beneath the same developer surface.

---

# E-022 Final Architecture

```text
                         APPLICATION
                             │
                             ↓
                     APPLICATION BROKER
                             │
                Format / ISA / Personality
                             │
            ┌────────────────┼─────────────────┐
            │                │                 │
         NATIVE           FOREIGN           VM-ONLY
            │                │                 │
            ↓                ↓                 ↓
      Native Evrosion   OS PERSONALITY      Guest OS
                             │
                    ┌────────┴────────┐
                    │                 │
                 Same ISA         Foreign ISA
                    │                 │
                    │           ISA TRANSLATOR
                    │                 │
                    └────────┬────────┘
                             ↓
                    COMPATIBILITY REALM
                             │
          ┌──────────────────┼─────────────────┐
          │                  │                 │
     Foreign VFS        Foreign State       Runtime
          │           Registry / etc.       APIs
          │                  │                 │
          └──────────────────┼─────────────────┘
                             ↓
                        HOST ADAPTERS
                             │
       ┌──────────┬──────────┼─────────┬──────────┐
       │          │          │         │          │
    Graphics    Audio     Network    Input     Storage
       │          │          │         │          │
     E-017      E-018      E-011     Native     E-010
```

VM fallback:

```text
Compatibility Resolver
        ↓
Required foreign semantics
cannot be reproduced safely
        ↓
Virtual Machine
        ↓
Foreign Kernel
        ↓
Paravirtual integration
        ↓
Evrosion
```

Compatibility state:

```text
Shared Immutable Runtime
          +
Private Compatibility Realm
          +
Versioned Compatibility Profile
          +
Optional ISA Translator
          =
Reproducible Foreign Application Environment
```

---

# E-022 Final Summary

**Compatibility model:** Layered Compatibility Fabric

**Native compatibility overhead:** Effectively zero when unused

**OS personality:** Userspace

**CPU translation:** Independent subsystem

**Kernel foreign policy:** No

**Generic foreign trap support:** Allowed

**Windows:** First-class compatibility priority

**Initial Windows implementation:** May use Wine/Proton-derived technology

**Permanent Linux dependency for Windows:** No

**Linux:** Native userspace personality

**Linux distro/runtime:** Separate from personality

**Foreign VFS:** Compatibility-local

**Foreign package managers:** Realm-only

**Foreign applications:** Evrosion AppIdentity

**Mutable foreign state:** Compatibility Realm

**Runtime content:** Immutable/shared

**Realm storage:** CoW/private by default

**Global Wine prefix:** No

**Shared Realms:** Deliberate security decision

**Host resource authority:** Evrosion capabilities only

**Foreign root/SYSTEM:** Realm-local identity only

**Foreign kernel drivers:** Never loaded into Evrosion kernel

**Graphics:** Translate toward E-017 early

**Audio:** Translate toward E-018 early

**Networking:** Translate toward E-011 early

**Storage:** Capability-backed E-010 integration

**ISA translation:** Independent and replaceable

**High-level API thunking:** Preferred

**Translation caches:** Disposable

**JIT/self-modifying code:** Supported through controlled translator/W^X model

**Windows NT synchronization/object semantics:** Implemented in personality using efficient native primitives

**Foreign installers:** Staged inside Realm

**Foreign self-updaters:** Realm-contained

**Compatibility profiles:** Per-app, versioned

**Quirks:** Local data, never global kernel hacks

**Compatibility cohorts:** E-019 managed

**32-bit support:** Through compatibility

**Native 32-bit kernel:** No

**VM:** Final fidelity fallback

**VM transition:** Explicit, never silent

**macOS/Darwin:** Architected, later/optional

**Android:** Architecturally possible later

**Testing:** Differential/reference behavior

**Quality:** Measured

**Failures:** E-020 Failure Capsules

**Native migration:** Supported conceptually

**Long-term destination:** Native Evrosion ecosystem

---

# Governing Principles

> **Compatibility adapts foreign software to Evrosion. Evrosion does not turn itself into the foreign operating system.**

> **Native software never pays for compatibility.**

> **Foreign OS personality and foreign CPU ISA are independent axes.**

> **Use the cheapest correct execution path.**

> **Translate at the highest semantic level available. Emulate instructions only where necessary.**

> **Reach native graphics, audio, networking, input, and storage paths as early as possible.**

> **Foreign operating-system policy remains outside the Evrosion kernel.**

> **A generic foreign-execution mechanism is acceptable. Linux-, Windows-, or Darwin-specific kernel architecture is not.**

> **Compatibility faithfully reproduces foreign behavior without making that behavior native Evrosion policy.**

> **Compatibility runtimes are immutable and shared. Mutable foreign state lives in isolated Compatibility Realms.**

> **Realm sharing is a deliberate security decision.**

> **Compatibility translates semantics. It never translates privilege.**

> **Foreign Administrator, SYSTEM, or root authority never automatically becomes Evrosion authority.**

> **Foreign kernel drivers never become Evrosion kernel modules.**

> **High-level native API adaptation is preferred over low-level emulation.**

> **JIT and self-modifying foreign code remain subject to host executable-memory security.**

> **Foreign installers and package managers modify compatibility state, not the host operating system.**

> **Quirks are scoped, versioned data—not global hacks.**

> **Compatibility environments must be reproducible, inspectable, and rollbackable.**

> **A VM is the last fidelity fallback, not the first compatibility answer.**

> **Moving an application into a VM is an explicit change of execution model, never a silent fallback.**

> **Reference operating-system behavior should be tested directly rather than guessed.**

> **Compatibility quality is measured, not described with vibes.**

> **Compatibility Failure Capsules record the exact environment that failed.**

> **Compatibility bootstraps the ecosystem. Native Evrosion remains the destination.**

**E-022 — DECIDED AND CLOSED.**
