# ADR-0060 — Sustained developer-session execution profile

Status: Accepted mechanism direction; implementation and runtime acceptance incomplete

Date: 2026-11-12

Decision level: B

## Context

The 0.1 desktop deliberately terminates after a bounded demonstration. Replacing
its stop tick with a huge integer would retain cumulative Job exhaustion and
could turn operation deadlines into effectively unbounded waits. M6 requires
legitimate manual use past those old limits while hostile work remains bounded.

## Decision

Use the separately built `m6-session` Kernel and `native-session` component
features. An explicit zero duration denotes this profile's lifetime only;
ordinary finite profiles reject it. It grants no CPU, object or endpoint rights.
Fresh finite operation deadlines remain checked against actual monotonic time.
An accepted operation never obtains more time by retrying or polling it.

Use the canonical Scheduler's renewable finite CPU windows, retaining cumulative
and ancestor accounting, and the canonical RPC/MemoryObject owners for guarded
cancellation. See ADR-0056 and ADR-0064. Timeout observation does not release a
callee's still-live memory credit. Uncertain disk mutations are never replayed.

`cargo ev session` starts a manual GTK session without generated input. It keeps
one runner-owned developer disk, an exclusive lock and exact ownership receipt.
Foreign, replaced or incomplete disk state is refused without formatting.
Explicit unlock on owner drop prevents a concurrently forked child's temporary
descriptor reference from extending that lock after the VM owner has retired.
The `finish` UART command currently requests checked retirement; GUI exit and
useful component failure states remain required work.

`cargo ev test session` is a separate scripted profile regression. Its success
could establish only that declared sequence, never human consent or complete
manual usability. Existing finite M0–M5 profiles retain their interpretation.
Bounded M6 RPC observations use the existing observation callback and a strict
session-only host decoder; diagnostic rows cannot replace completion evidence.

Session text and protected action keys share one pending-frame credit, one
nonwrapping sequence and the actual Input drain barrier. Text cannot launch,
select a file or approve a grant. Shell forwards it only to a live focused App,
outside picker/managed dialogs. Pointer integration is still incomplete.

## Evidence and open gates

The first linked integration census refused 264,960 bytes against the existing
262,144-byte stack. ADR-0065 removes duplicate boot-information ownership; the
second full build measured 251,696 bytes and booted, then failed on a Block read
deadline. Both failures are retained in `docs/status/evidence/`. That static
census is not a formal whole-program or runtime stack high-water proof.

Focused frontend ownership, Core, ATA cleanup and Input/Shell policy tests pass
in their recorded scopes. Real sustained use, competing abuse containment,
timeout recovery, editable persistence, pointer input, bounded long-running log
retention and complete resource retirement remain required by M6-02. A terminal
VM abort with retained owners is fail-closed and does not satisfy those gates.

The owner-approved VM release amendment changes physical qualification timing
only. No session profile result establishes physical-device qualification or
waives networking, authenticated acquisition or offline recovery requirements.
