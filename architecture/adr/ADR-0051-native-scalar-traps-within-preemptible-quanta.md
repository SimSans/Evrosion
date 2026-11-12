# ADR-0051 — Native scalar traps within preemptible quanta

Status: Accepted bounded implementation refinement; bounded physical verification passed.
Date: 2026-11-11. Documented mechanism refinement; no foundational guarantee changes.

The desktop reference executor previously yielded its actual scheduler thread
on every nonblocking syscall, including each mediated port instruction and clock
query. This makes transport capture a forced scheduling boundary. The ATA source
performs one budget clock query plus one mediated data-port access for each of
256 words in a sector: at least512 scalar traps before command/status overhead.
Every such trap rotated through polling actors before the driver continued.

The [fourth actual Native run](../../docs/release/0.1-preview.md#validation-and-provenance)
completed Home and installation, then exhausted the unchanged16,384-tick world
before candidate start:473,670 transitions,189 calls/188 replies and one delivered
Root-to-Block request. Immutable package caching was safe but did not resolve the
bound. A single sampled instruction inside hashing was insufficient to establish
the dominant total cost; the exact ATA loop and forced switching explain a
substantial avoidable transport overhead. Actual capture counters will quantify it.

For Native execution, a nonblocking scalar syscall may return to its current
Running thread within the same preemptible quantum. The executor retains the
actual Dispatch rather than illegally redispatching a busy CPU, and rechecks
its live Process/Thread/Job association. IRQ32 charges actual CPU use and yields;
explicit Yield, blocking, exit and fault release the runner as before. Scheduler
time advancement, global finite bounds, quotas, protected IPC, capability checks,
actual saved contexts, mapping ownership and CR3 restoration remain mandatory.
No busy user can suppress IRQ preemption through a syscall loop.

This refinement introduces no bulk-transfer syscall, raw pointer, port grant or
new authority. A new bulk port API would expand the permission and buffer-lifetime
surface without being needed for this immediate cost. Growing world limits
would retain the artificial switching overhead. The historical Desktop fixture
keeps its existing trap-by-trap behavior so its accepted experiment stays distinct.
The Native path is exercised by the actual multi-actor lifecycle with unchanged
limits and actual timer/capture/port/continuation counters. Its kernel stack
census, resource retirement and independent disk/pixel checks must also pass.
Counters are diagnostic observations, never completion or health receipts.

The [six-phase physical Native proof](../../docs/release/0.1-preview.md#validation-and-provenance)
passes with the unchanged bounds. The complete graphical phase uses7,193ticks
and382 matched calls, with actual port/syscall continuation and timer quota
charges. All six boots complete real retirement and independent disk/pixel
checks. This verifies the bounded mechanism, not general performance, M5 or0.1.
