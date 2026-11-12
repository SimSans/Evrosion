# Evrosion — E-023 Performance & Resource Model

**Status: ARCHITECTURAL DIRECTION DECIDED AND CLOSED**

Evrosion will use a:

> **Hierarchical Resource Contracts with Causal QoS, Pressure-Driven Adaptation, and Work-Conserving Resource Control**

The central objective is:

> **When the machine is overloaded, Evrosion should know what the person is waiting for and protect that work first.**

---

# E-023.1 — Jobs Are the Resource Governance Unit

E-004 already defines:

```text
Job
 ├── Process
 ├── Process
 └── Worker
```

E-023 makes the **Job tree** the primary resource-governance, fairness, and accounting hierarchy.

An application must not gain more resources merely by creating more processes.

Example:

```text
App A
├── process 1
├── process 2
├── process 3
...
└── process 200
```

must not automatically receive more total system entitlement than:

```text
App B
└── process 1
```

simply because App A created more processes.

The Job remains the workload boundary.

---

# E-023.2 — Hierarchical Resource Contracts

Each important Job may receive a:

> **Resource Contract**

A Resource Contract defines how the Job participates in contention across different system resources.

Resources share a governance/accounting model.

They do **not** pretend to have identical semantics.

---

# E-023.3 — No Universal Priority Number

Evrosion explicitly rejects a single global field such as:

```text
priority = 7
```

for every resource.

CPU time is not RAM.

RAM is not GPU memory.

GPU latency is not storage throughput.

Network cost is not thermal headroom.

Different resources require different control semantics.

---

# E-023.4 — CPU Contract

Possible CPU contract properties may include:

```text
weight
budget
period
deadline
latency class
burst allowance
efficiency preference
```

E-004 remains authoritative for actual CPU scheduling mechanisms.

---

# E-023.5 — Memory Contract

Possible memory contract properties may include:

```text
target
soft ceiling
hard ceiling
protected amount
reclaimability
working-set importance
```

E-005 remains authoritative for actual memory management.

---

# E-023.6 — Storage I/O Contract

Possible storage properties may include:

```text
weight
latency target
bandwidth ceiling
burst allowance
maintenance class
durability importance
```

---

# E-023.7 — GPU Contract

Possible GPU properties may include:

```text
scheduling weight
memory budget
latency intent
queue limits
compute budget
presentation importance
```

E-017 remains authoritative for GPU/display architecture.

---

# E-023.8 — Network Contract

Possible network properties may include:

```text
relative priority
bandwidth policy
metered allowance
background eligibility
latency intent
```

E-011 remains authoritative for networking.

---

# E-023.9 — Power Contract

Possible power-related properties may include:

```text
efficiency preference
background eligibility
battery sensitivity
thermal tolerance
performance intent
```

Applications do not control hardware clocks directly.

---

# E-023.10 — Other Bounded Resources

The same governance model may apply to resources such as:

```text
process count
object count
open handles
accelerator time
AI token budget
AI monetary budget
network cost
```

where appropriate.

---

# E-023.11 — Applications Request Intent

Applications may declare intents such as:

```text
interactive
background
latency-sensitive
throughput-oriented
deadline-sensitive
energy-flexible
```

These are requests.

They are not authority.

---

# E-023.12 — Evrosion Grants Resource Authority

Conceptually:

```text
Application Intent
       ↓
Resource Policy
       ↓
Granted Resource Contract
```

Evrosion decides what is actually granted.

---

# E-023.13 — Resource Evidence

Policy may consider evidence such as:

```text
foreground state
surface visibility
active user interaction
audible media
explicit user preference
trusted system role
battery state
thermal state
hardware capability
```

No single signal grants unlimited priority.

---

# E-023.14 — Foreground Is Evidence, Not Unlimited Priority

A foreground application may deserve favorable latency treatment.

It does not automatically receive:

```text
all CPU
all memory
all GPU
all storage bandwidth
```

Foreground status cannot override:

- Realtime deadlines
- System safety
- Secure Attention
- Trusted Control
- Hardware thermal limits
- Critical recovery work

---

# E-023.15 — Causal Performance

Evrosion should optimize the work the user is actually waiting for.

Example:

```text
User click
 ↓
Shell
 ↓
Application
 ↓
Storage Service
 ↓
Filesystem
 ↓
NVMe Driver
 ↓
Decoder
 ↓
GPU
 ↓
Compositor
 ↓
Display
```

The latency belongs to the whole chain.

Not merely the foreground process.

---

# E-023.16 — Responsiveness Context

E-008 Work Contexts should be able to carry a short-lived:

> **Responsiveness Context**

Example:

```text
User Interaction #891
latency-sensitive
short lifetime
```

This context follows causally related work across subsystem boundaries.

---

# E-023.17 — Causal QoS

Participating subsystems may recognize:

> This operation is currently blocking a real user interaction.

They may then temporarily provide:

```text
lower queue latency
short burst capacity
higher scheduling preference
faster wake
```

within policy limits.

---

# E-023.18 — Urgency Is Temporary

A temporary responsiveness boost disappears when the causal operation finishes.

No permanent process inflation.

---

# E-023.19 — Bounded Urgency Inheritance

When work crosses into another service:

```text
Inherited urgency
≤ caller's granted urgency
```

and:

```text
Inherited urgency
≤ callee/service maximum
```

The callee cannot receive arbitrary stronger authority merely because it was called.

---

# E-023.20 — No Priority Laundering

A low-importance workload must not become high priority simply by sending work through a privileged service.

Example:

```text
Background Job
     ↓
Storage Service
```

does not transform the work into critical system I/O merely because the Storage Service is trusted.

---

# E-023.21 — Causal Resource Accounting

Where practical, work executed by a system service on behalf of another Job should be attributed back to the originating Job.

Example:

```text
Browser Job
    ↓
Storage Service
    ↓
Disk I/O
```

Accounting may report:

```text
Browser-caused I/O
```

rather than hiding everything under:

```text
Storage Service
```

---

# E-023.22 — Service Internal Work Is Separate

A service's own maintenance remains charged to the service itself.

Example:

```text
Storage scrub
```

is not charged to a browser merely because a browser also uses storage.

---

# E-023.23 — Performance Pressure Measures Delay

Simple utilization is not enough.

Examples:

```text
CPU = 100%
```

may be perfectly healthy if no important work is waiting.

Likewise:

```text
RAM = 95% used
```

may simply mean useful caching.

The important question is:

> **Is resource scarcity delaying useful work?**

---

# E-023.24 — Resource Pressure Signals

Major resources should expose meaningful native pressure measures.

Possible examples:

```text
CPU:
runnable delay

Memory:
reclaim delay
page-fault delay
compression delay
swap delay
thrashing
refaults

Storage:
queue delay
tail latency

GPU:
queue delay
scheduling delay

Network:
local queue delay
local congestion

Thermal:
performance lost to throttling

Power:
energy constraint
battery pressure
```

---

# E-023.25 — Do Not Create One Fake Pressure Percentage

CPU pressure, memory pressure, GPU pressure, and thermal pressure should remain semantically distinct.

Higher-level policy may combine them.

The underlying observations remain resource-specific.

---

# E-023.26 — Detect Thrashing

Memory pressure is not simply:

```text
free memory low
```

Evrosion should detect effects such as:

```text
refault storms
swap churn
compression churn
working-set instability
reclaim stalls
```

A machine with more free RAM may still be suffering worse memory behavior than one with less.

---

# E-023.27 — Target, Soft Limit, Hard Limit

Where useful, resource contracts should distinguish:

```text
TARGET
SOFT LIMIT
HARD LIMIT
```

---

# E-023.28 — Resource Target

A target describes normal desired usage.

The Job may exceed it when resources are abundant.

---

# E-023.29 — Soft Limit

A soft limit means:

> This usage may be exceeded when capacity exists, but under contention the Job should be pushed back toward the limit.

Soft limits provide pressure control before failure.

---

# E-023.30 — Hard Limit

A hard limit is an actual enforcement boundary.

The Job may not consume beyond it.

Hard limits should be used deliberately rather than as the only form of resource control.

---

# E-023.31 — Work-Conserving Design

Evrosion should not leave useful capacity idle merely because a workload has low importance.

Example:

```text
16 CPU cores
foreground uses 2
background compiler wants 14
```

The compiler may use the remaining cores.

---

# E-023.32 — Importance Governs Contention

Principle:

> **Low importance affects competition, not access to unused capacity.**

When there is no competition:

```text
background work may run fast
```

When interactive demand arrives:

```text
background work yields quickly
```

---

# E-023.33 — Opportunity Work

Background tasks such as:

```text
indexing
backup
scrubbing
updates
compilation
background AI
```

may belong to an:

> **Opportunity Work**

class.

Meaning:

```text
Use spare resources aggressively.
Yield rapidly when more important work appears.
```

---

# E-023.34 — Background Does Not Mean Permanently Slow

A backup running overnight on an idle machine should not be artificially throttled to tiny throughput merely because it is background work.

Use idle capacity.

---

# E-023.35 — Interaction Bursts

User interaction is naturally bursty.

A click may temporarily require fast:

```text
CPU
storage
GPU
memory
```

for a short period.

Evrosion should support bounded short-lived burst behavior.

---

# E-023.36 — Burst Credits

A Responsiveness Context may receive temporary:

> **Burst Credits**

allowing short controlled excursions beyond normal soft budgets.

Burst credits expire automatically.

---

# E-023.37 — Burst Credits Are Not Permanent Priority

Once the interaction finishes:

```text
burst ends
```

The workload returns to its normal contract.

This prevents permanent priority inflation.

---

# E-023.38 — Burst Abuse Protection

Applications cannot manufacture unlimited responsiveness contexts merely to remain boosted.

Burst creation should be limited by:

```text
real user interaction
trusted system event
policy
rate limits
budget
```

Causal relationships must remain verifiable.

---

# E-023.39 — Critical Responsiveness Floor

Even under extreme saturation, certain operations must remain viable.

Examples:

```text
input
Secure Attention
Trusted Control
supervisor
recovery
critical storage
display recovery
audio deadline path
```

---

# E-023.40 — Protection Is Resource-Specific

Examples:

```text
CPU
→ protected scheduling opportunity

Memory
→ wired/nonpageable state + emergency reserve

Storage
→ bounded priority queues

GPU
→ protected scheduling opportunity

IPC
→ bounded control queues
```

Do not invent one fake universal mechanism.

---

# E-023.41 — Protected When Needed, Available When Safe

Critical protection should not unnecessarily waste idle hardware.

Example:

A critical service may have guaranteed CPU scheduling access without permanently reserving an idle core.

---

# E-023.42 — Resource Policy Service

Evrosion should provide a logical:

> **Resource Policy Service**

responsible for slow-moving high-level policy.

Conceptually:

```text
                RESOURCE POLICY SERVICE
                         │
                 Resource Contracts
                         │
       ┌─────────┬───────┼───────┬─────────┐
       │         │       │       │         │
      CPU      Memory  Storage  GPU     Network
```

---

# E-023.43 — Policy Service Is Not on the Fast Path

Fast resource decisions remain local.

Examples:

```text
CPU Scheduler
Memory Manager
Storage Queue Controller
GPU Device Service
Network Stack
```

use cached/current resource contracts.

They do not ask a central daemon for every operation.

---

# E-023.44 — Policy Service Failure

If Resource Policy Service crashes:

```text
CPU still schedules
Memory still works
GPU still submits
Storage still works
Network still works
```

Existing contracts remain active.

Subsystems fall back to conservative defaults if necessary.

F-010 remains satisfied.

---

# E-023.45 — CPU Scheduling

E-004 remains authoritative for:

```text
Scheduling Contexts
fair scheduling
budget/period
priority
deadline scheduling
bounded donation
realtime
```

E-023 adds broader workload policy and pressure feedback.

---

# E-023.46 — Heterogeneous CPU Support

Evrosion must not assume all CPU cores are identical.

Possible hardware differences include:

```text
performance cores
efficiency cores
NUMA
cache domains
frequency domains
different microarchitectures
```

Policy should consume hardware capability descriptions rather than hard-coded vendor assumptions.

---

# E-023.47 — CPU Placement

Where hardware supports meaningful differences:

```text
latency-sensitive burst
→ suitable performance resources
```

and:

```text
background opportunity work
→ efficient resources
```

may be preferred.

Correctness remains independent of CPU class.

---

# E-023.48 — Applications Do Not Control CPU Frequency

Applications request:

```text
latency
throughput
efficiency
deadline
```

They do not request:

```text
4.8 GHz
```

Hardware policy decides clocks and power states.

---

# E-023.49 — Memory Policy

E-005's pressure ladder remains:

```text
trim
reclaim
compress
demote
swap
throttle
freeze
cooperative release
terminate Job
```

E-023 provides Job importance and causal context to guide decisions.

---

# E-023.50 — Memory Reclaimability

Memory may be classified or inferred as:

```text
critical working set
ordinary working set
cache
reconstructable data
temporary buffers
```

Reclaim should prefer cheap-to-reconstruct memory where practical.

---

# E-023.51 — Hints Are Not Absolute Truth

Applications may provide reclaimability hints.

The OS may compare hints against observed behavior.

An application cannot make all its memory untouchable merely by declaring:

```text
critical = true
```

---

# E-023.52 — OOM Remains Job-Oriented

If termination becomes unavoidable:

> **OOM is controlled recovery, not random murder.**

The decision should consider:

```text
user importance
restartability
durability
resource consumption
background state
working-set behavior
```

---

# E-023.53 — Storage Classes

Storage scheduling should distinguish between workloads such as:

```text
interactive latency
bulk throughput
background maintenance
durability-critical writes
```

---

# E-023.54 — Interactive I/O

Example:

```text
User opens document
```

should not sit behind a huge background scan merely because the scan entered the queue earlier.

---

# E-023.55 — Idle Storage Throughput

When no interactive work exists:

```text
scrub
backup
indexing
update acquisition
```

may use the storage device aggressively.

Work-conserving behavior applies.

---

# E-023.56 — Durability Beats Performance Policy

Once E-010 requires data to become durable:

performance policy cannot silently discard or violate that requirement.

Correctness outranks speed.

---

# E-023.57 — GPU Accounting

E-017 GPU resource accounting should include concepts such as:

```text
GPU time
GPU memory
queue latency
submission behavior
compute load
```

at Job level where practical.

---

# E-023.58 — GPU Opportunity Work

Background GPU compute may use idle hardware aggressively.

When interactive rendering/compositor work arrives:

```text
background compute yields
```

within hardware capabilities.

---

# E-023.59 — No Magical Gaming Mode

Applications may request:

```text
low presentation latency
high throughput
```

They do not receive universal system dominance by declaring:

```text
gaming = true
```

Evrosion considers:

```text
visibility
fullscreen state
user preference
thermal state
battery state
competing deadlines
```

---

# E-023.60 — Realtime Media

E-018 retains special deadline semantics for real-time audio/media work.

A real deadline is fundamentally different from a generic high priority.

---

# E-023.61 — Admission Control

Strict realtime/deadline contracts require capacity validation.

Example:

```text
Requested:
1 ms audio deadline
```

Evrosion determines whether available hardware/resources can actually support it.

Possible result:

```text
granted
```

or:

```text
cannot guarantee requested contract
```

---

# E-023.62 — Never Grant Fake Realtime

If the system cannot provide a requested guarantee:

say so.

Do not grant a label whose promised semantics cannot be honored.

---

# E-023.63 — Competing Realtime Clients

When multiple strict realtime/deadline clients compete:

Evrosion must perform admission control across the relevant resource domain.

The system may:

```text
accept both
degrade one
reject new guarantee
ask user/policy
```

depending on declared contracts.

It must not overcommit hard guarantees invisibly.

---

# E-023.64 — Network Policy

E-011 remains authoritative for network paths.

E-023 may provide workload-level QoS.

Example:

```text
video call
```

may receive local latency preference over:

```text
background update
```

---

# E-023.65 — Local vs External Network Delay

Evrosion should distinguish:

```text
local queue pressure
```

from:

```text
remote Internet/server latency
```

where possible.

The OS can control its local queues.

It cannot schedule the entire Internet.

---

# E-023.66 — Metered Networks

Resource contracts may include:

```text
unmetered allowed
metered restricted
roaming restricted
background disabled
```

according to user policy.

---

# E-023.67 — Monetary Resources

E-021 AI cost budgets demonstrate that resource control can include non-hardware cost.

A Job may consume:

```text
network cost
AI API cost
cloud resource cost
```

subject to explicit budgets.

---

# E-023.68 — Power & Thermal Service

Evrosion should provide a logical:

> **Power & Thermal Service**

that exposes hardware-independent information such as:

```text
battery state
charging state
thermal headroom
throttling state
energy estimate
performance domains
efficiency domains
```

---

# E-023.69 — Thermal Pressure

Thermal throttling should be observable as resource pressure.

Example:

```text
CPU available performance reduced by thermal constraint
```

where hardware allows meaningful measurement.

---

# E-023.70 — Performance Per Watt

Laptop policy should consider:

> performance per watt

not merely peak completion speed.

Efficient scheduling can:

```text
extend battery
reduce heat
reduce fan noise
preserve burst headroom
```

---

# E-023.71 — User Power Modes

Evrosion may expose simple policies such as:

```text
Quiet
Balanced
Performance
Battery Saver
```

These are high-level policy envelopes.

---

# E-023.72 — Power Modes Are Not Dumb Global Switches

Example:

```text
Quiet
→ favor efficient background execution
→ reduce unnecessary fan/thermal load
→ still preserve interaction/audio deadlines
```

Performance:

```text
→ permit larger power envelope
→ favor speed where useful
```

Neither disables hardware safety.

---

# E-023.73 — Layer 1 Resource UX

Layer 1 should expose very little complexity.

Possible concepts:

```text
Battery Saver
Balanced
Performance
```

and understandable warnings such as:

> This application is slowing down your computer.

---

# E-023.74 — Layer 2 Resource UX

Layer 2 may expose:

```text
per-app performance preference
background activity
CPU use
memory use
GPU use
battery use
network use
resource limits
```

without requiring knowledge of scheduling internals.

---

# E-023.75 — Layer 3 Resource UX

Layer 3 may inspect the full Job/resource hierarchy.

Example:

```text
Desktop Session
├── Browser Job
├── Game Job
└── Update Job
```

with resource contracts, pressure and usage.

---

# E-023.76 — Layer 3 Owner Control

Layer 3 may deliberately:

```text
change budgets
alter weights
pin CPU placement
grant realtime
change memory ceilings
change GPU budgets
override background policy
```

subject only to hardware reality and explicit warnings.

---

# E-023.77 — Graceful Overload Philosophy

When demand exceeds available hardware, Evrosion should degrade deliberately.

Possible progression:

```text
1. Stop speculative/prefetch work
2. Trim cheap caches
3. Throttle opportunity/maintenance work
4. Reduce optional quality
5. Delay/freeze background Jobs
6. Reclaim/compress/swap
7. Reduce nonessential compatibility/AI work
8. Terminate restartable low-importance Jobs if unavoidable
```

Exact ordering may vary by resource and workload.

---

# E-023.78 — User Work Is Protected First

Under overload, active user interaction and critical recovery paths should generally degrade after optional/background work.

This does not override true hard realtime or safety requirements.

---

# E-023.79 — Quality Degradation Is Explicit

If software supports adaptive quality:

```text
lower video quality
reduce background rendering
reduce AI concurrency
pause indexing
reduce prebuffer
```

the change should be observable.

Do not silently corrupt behavior.

---

# E-023.80 — Pressure Notifications

Applications/services may subscribe to events such as:

```text
Memory Pressure
GPU Pressure
Thermal Pressure
Power Pressure
```

and voluntarily adapt.

---

# E-023.81 — Cooperation Is Optimization, Not Enforcement

An application ignoring pressure notifications cannot disable system resource control.

Evrosion still enforces contracts.

---

# E-023.82 — Cross-Resource Coordination

CPU, memory, GPU, storage and thermal policy can conflict.

Example:

```text
GPU workload wants higher performance
thermal state says reduce power
foreground interaction wants low latency
battery saver wants efficiency
```

Evrosion needs policy arbitration.

---

# E-023.83 — Policy Precedence

A useful ordering principle is:

```text
Correctness / hardware safety
        ↓
Hard admitted realtime guarantees
        ↓
Trusted critical responsiveness
        ↓
Explicit user policy
        ↓
Causal foreground responsiveness
        ↓
Normal workload fairness
        ↓
Background opportunity work
```

This is a policy principle, not a single universal scheduler number.

---

# E-023.84 — Cross-Resource Decisions Stay Explainable

If an application's performance is reduced because of thermal or battery constraints, Evrosion should be able to explain that.

Example:

> This workload is being limited because the system is thermally constrained.

Not:

> Performance reduced for unknown reason.

---

# E-023.85 — Shared Resource Accounting

Some resources are shared between Jobs.

Examples:

```text
filesystem cache
shared library pages
GPU buffers
compatibility runtime
shared code pages
```

Evrosion should not blindly charge the full physical amount to every participant.

---

# E-023.86 — Physical vs Logical Accounting

Resource accounting may distinguish:

```text
logical usage
physical unique usage
shared usage
```

where meaningful.

Example:

Two applications mapping the same immutable runtime should not each appear to consume the entire physical copy independently.

---

# E-023.87 — Shared Resource Policy

Shared caches should be accounted and reclaimed based on:

- Consumers
- Reconstructability
- Usage frequency
- Pressure
- Ownership
- Physical cost

without requiring perfect per-byte attribution.

Accuracy is useful.

Architectural insanity is not.

---

# E-023.88 — Performance Observability

E-020 diagnostics should answer:

> What resource currently limits this Job?

Possible answers:

```text
CPU
Memory
Storage
GPU
Network
Thermal
Dependency
```

---

# E-023.89 — Causal Performance Explanation

Example:

```text
Frame #723

Compositor work:
2.1 ms

GPU queue wait:
13.8 ms

Cause:
background compute queue

Action:
background GPU work throttled
```

This is preferable to:

> System is slow.

---

# E-023.90 — Performance Attribution

Resource dashboards should avoid hiding workload cost under system processes.

Where practical:

```text
Resource consumed on behalf of Browser
```

is more useful than:

```text
System Service 40% CPU
```

when the Browser caused the work.

---

# E-023.91 — Tail Latency Matters

Evrosion should optimize:

> **user-perceived latency under contention**

not merely maximum throughput on an idle machine.

---

# E-023.92 — Contention Benchmarks

Performance testing should include situations such as:

```text
launch app while update downloads
play audio while compiling
drag window during storage saturation
open menu during memory pressure
game while indexer runs
video call while backup transfers
```

---

# E-023.93 — Raw Throughput Still Matters

Evrosion should still benchmark:

```text
memory bandwidth
storage throughput
network throughput
GPU throughput
compute throughput
```

But these are not sufficient by themselves.

---

# E-023.94 — Performance SLOs

Evrosion may eventually define measurable targets for:

```text
input-to-frame latency
application launch latency
wake latency
audio XRUN rate
frame misses
resource stall time
memory thrashing
storage tail latency
energy per workload
idle power
```

Different hardware tiers may have different targets.

---

# E-023.95 — Hardware-Aware Expectations

A 4 GB laptop and a 64 GB workstation should not use identical resource assumptions.

Policy should adapt to:

```text
available RAM
CPU topology
storage class
GPU capability
battery state
thermal capability
```

---

# E-023.96 — No Arbitrary High Minimum

E-003/F-006 remain authoritative.

Evrosion scales down to hardware where technically practical rather than demanding that hardware scale up to Evrosion.

---

# E-023.97 — Compatibility Is a Normal Workload

E-022 Compatibility Realms remain normal Jobs.

A Windows game and a native game both participate in the same resource framework.

Compatibility overhead may be separately attributable where useful.

---

# E-023.98 — Native Software Still Pays No Compatibility Tax

Compatibility resource controllers/services do not remain active merely because compatibility exists.

Unused compatibility contributes effectively no runtime cost.

---

# E-023.99 — AI Is a Normal Workload

E-021 AI Sessions are Jobs.

They receive normal:

```text
CPU
Memory
GPU/NPU
Network
time
financial
```

budgets.

---

# E-023.100 — AI Does Not Receive Resource Privilege

An AI workload does not become more important than the user simply because it is “AI.”

Background inference yields to interactive work.

---

# E-023.101 — Resource Control Architecture

```text
                         USER INTENT
                              │
                              ↓
                    RESOURCE POLICY SERVICE
                              │
                     RESOURCE CONTRACTS
                              │
                              ↓
                           JOB TREE
                              │
      ┌──────────┬────────────┼───────────┬──────────┐
      │          │            │           │          │
     CPU       Memory       Storage      GPU      Network
      │          │            │           │          │
 Local       Memory       I/O Queue    Device      Path /
Scheduler    Manager       Control     Service      QoS
      │          │            │           │          │
      └──────────┴────────────┼───────────┴──────────┘
                              │
                     PRESSURE FEEDBACK
                              │
                              ↓
                    RESOURCE POLICY SERVICE
```

The Resource Policy Service remains outside the fast path.

---

# E-023.102 — Causal QoS Overlay

```text
USER ACTION
    ↓
Responsiveness Context
    ↓
Application
    ↓
IPC
    ↓
Service
    ↓
Storage / GPU / Network / Memory
    ↓
Result
```

Causal urgency follows the actual request rather than permanently boosting unrelated work.

---

# E-023 Final Summary

**Resource unit:** Job

**Resource hierarchy:** Job tree

**Universal priority number:** No

**Resource contracts:** Multi-dimensional

**Application role:** Request intent

**OS role:** Grant/enforce policy

**Foreground:** Evidence, not unlimited authority

**Causal QoS:** First-class

**Responsiveness Context:** Short-lived and propagated

**Priority inheritance:** Bounded

**Resource laundering through services:** Prevented

**Resource attribution:** Causal where practical

**Pressure measurement:** Stall/delay based

**Single global pressure percentage:** No

**Memory thrashing detection:** Yes

**Target / soft / hard limits:** Supported where appropriate

**Work-conserving:** Yes

**Background work:** Uses spare capacity, yields under contention

**Burst credits:** Short-lived and bounded

**Critical responsiveness:** Protected under saturation

**Central policy daemon on fast path:** No

**Policy-service failure:** Cached contracts/conservative defaults

**Heterogeneous CPUs:** First-class

**App CPU frequency control:** No

**Storage:** Latency/throughput/durability aware

**GPU:** Job-accounted and contention-aware

**Gaming magic flag:** No

**Realtime:** Admission controlled

**Fake realtime guarantees:** No

**Network:** Local QoS plus metered/cost policy

**Power:** First-class

**Thermal:** First-class pressure source

**Performance per watt:** First-class

**User power modes:** Policy envelopes

**Overload:** Graceful degradation

**Pressure notifications:** Cooperative plus enforcement

**Cross-resource arbitration:** Explicit policy precedence

**Shared-resource accounting:** Logical/physical distinction where useful

**Performance observability:** E-020 integrated

**Primary optimization goal:** Tail latency under contention

**Hardware scaling:** Adaptive

**Compatibility workloads:** Normal Jobs

**AI workloads:** Normal Jobs

---

# Governing Principles

> **The unit of resource fairness is the Job, not the number of processes it creates.**

> **Resources share policy and accounting, not fake identical semantics.**

> **Applications request resource intent. Evrosion grants resource authority.**

> **Foreground state is evidence of importance, not unlimited priority.**

> **Performance follows causality: accelerate the work the user is actually waiting for.**

> **Urgency may propagate through dependencies only within bounded granted authority.**

> **System services must not become resource-laundering proxies.**

> **Measure resource pressure by experienced delay and lost productivity, not utilization alone.**

> **Soft budgets control pressure before hard limits cause failure.**

> **Unused capacity should remain usable.**

> **Background work may run fast when nobody needs the resources and yield quickly when somebody does.**

> **Short interactive bursts deserve short-lived burst resources, not permanent priority inflation.**

> **Critical responsiveness must survive saturation.**

> **Protected when needed. Available when safe.**

> **No central policy daemon belongs on the scheduling fast path.**

> **If the policy service fails, cached local resource contracts keep the machine functioning.**

> **True realtime/deadline guarantees require admission control. Never promise resources the machine cannot provide.**

> **Performance policy never weakens correctness, durability, isolation, or hardware safety.**

> **Thermal and power limits are real resource constraints, not mysterious slowdowns.**

> **Resource pressure degrades optional/background work before active user work.**

> **Cross-resource conflicts must resolve according to explicit policy rather than accidental scheduler behavior.**

> **Shared resources require honest physical/logical accounting rather than naïve double charging.**

> **Resource accounting follows causal work where practical.**

> **Compatibility and AI are ordinary workloads under the same resource framework.**

> **Optimize tail latency under contention, not merely benchmark throughput on an idle machine.**

**E-023 — DECIDED AND CLOSED.**
