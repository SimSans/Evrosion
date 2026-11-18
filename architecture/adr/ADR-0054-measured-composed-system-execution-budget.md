# ADR-0054 — Measured composed System execution budget

Status: Accepted bounded experiment refinement; complete five-cold execution verified.
Date: 2026-11-11. Founder mandate Level B; health and authority guarantees stay.

## Evidence and problem

The first composed System attempt (local engineering archive)
retains both source-bound System/Recovery builds and the actual failed VM before
follow-up changes. Good's durable Admission is followed by fresh Root query Q2
at tick4888, actual critical Shell readiness at4917 and fresh Root Q3 at4920.
This meets the unchanged anchored64-tick readiness window. The real System probe,
later fresh liveness, durable health and KnownGood promotion complete. All15
graphical stages, actual App/Shell faults and replacement complete as well.

The overall16,384-tick execution world then expires with751 accepted calls and
750 replies while the actual Root waits on Block. Bad2 staging acknowledged;
independent checksum-valid disk inspection finds System operation5/sequence6,
Good1 active and KnownGood, Bad2 staged, and the real Good1/boot1 probe. Activation
operation6 is not committed. App data remains usable1001. No cold Bad/Good or
recovery execution is accepted from this failed run.

This is an experiment duration limit, not failed critical health or Root CPU
exhaustion. The trace charges Root929 of65,536 ticks and Block14,068 of16,384.
The captured actors total16,384 IRQ ticks;510,724 transitions remain below the
existing8,000,000 transition limit. Root and actor Jobs are siblings beneath the
boot creator, so these values must not be described as Root's child CPU charges.

## Decision

Only the authenticated Native catalogue's **SystemManaged** mode selects a
32,768-tick overall execution world. M4, Native Standalone and independent
Recovery retain16,384. Share the mode-dependent budget between the actual
executor and strict host validators; bind dedicated validation to the retained
catalogue/fixture, not merely a self-declared serial label. Older Native traces
without the new mode receipt retain their original16,384 bound.

This changes the finite extent of the composed demonstration. It does not
extend or reset the critical health window, synthesize progress, relax a source
identity check or permit authority before Healthy. Root receives the actual new
world stop through the existing startup argument; no wire layout or authority
grant changes. The owner confirmation window remains4,096 ticks; picker maximum
lifetime and the existing stop-relative RPC allowance already accommodate it.

All CPU credits and frame quotas stay fixed: Root65,536 CPU, each actor16,384,
boot ancestor262,144; the8M transition limit, guards and resource retirement
remain mandatory. In particular, Block has only2,316 CPU ticks left in the
failed run. A later actual Block-budget failure requires its own preserved
measurement and decision; this refinement does not preauthorize that increase.

## Alternatives and limits

Stage and Activate now obtain their highest-generation/staged projection from
the retained last-confirmed SystemView. All System mutations already update
that view. A missing view refuses; the sole State.system_apply still independently
reopens and validates current Store state, commits/readbacks and preserves
uncertainty fencing. This removes two redundant metadata reads without treating
the cache as authority or skipping durable revalidation. Actual phase execution
must confirm its resource effect.

Removing Store readback, weakening health or accepting an unfinished activation
would defeat the proof. Future removal of demonstrably redundant work may help,
but this trace shows real accepted Block work rather than a stalled queue or
Root hashing loop. Splitting the demonstration across additional cold boots
would change its coherent session and boot-serial chain. A separate bounded
System experiment duration preserves the intended end-to-end proof directly.

The larger world does not promise that every actor quota suffices, establish
production scheduling policy or complete M5/0.1. Require mode/overbound refusal
tests, unchanged prior-profile checks, actual linked stack/frame preflights and
the complete five-cold execution with independent disk/source/identity joins.
Every failed attempt remains immutable.

## First measured result

The next retained attempt (local engineering archive)
independently accepts the complete first SystemFull phase:16,643 elapsed ticks,
753 matched calls, actual App/Shell replacement, all10 timing records, committed
Bad2 selection and complete retirement. Block uses14,166 of16,384 CPU ticks;
Root uses979 of65,536. The original world would still be259 ticks short after
the redundant-read optimization; no actor CPU increase was needed.

Its next cold Bad VM reaches actual health failure and ordinary RootExit0, but
the generic host parser rejects the legitimate Shell fault before the first GUI
frame. The outer attempt remains failed. This validates the bounded execution
refinement for the first phase, not the complete five-cold recovery proof.

The later complete five-cold proof (local engineering archive)
passes under this bound after ADR-0055 removes the self-notification deadlock.
That Full phase takes15,746 ticks with Block13,413/16,384; all CPU credits remain
unchanged. Earlier measurements remain historical facts, not promises that
every future/full or supported-host workload must finish within16,384 ticks.
