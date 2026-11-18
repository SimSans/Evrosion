# ADR-0097 — Required-subject presentation ordering

Status: Proposed private implementation; actual VM qualification pending.
Date: 2026-11-13
Owners: Internal Root startup-health and desktop delivery
Related: ADR-0096; downloaded-health admission and authenticated content join

## Context

The retained d5d51 System6 attempt completed real B acquisition and standalone
selection. Its managed B emitted an actual App Present, then a Note Read at
tick22163 after the first post-admission Root anchor22125. Root had accepted
an AppRestored Shell control; Shell presented and completed its real Input
barrier at22200. Root next sampled itself at22214, beyond the original64-tick
health window, and recorded MissingProgress. No App Critical was observed.
The exact Note handler entry was not measured. Source shows that unsettled UI
controls hold staged Note work and health ticking; this supports a presentation
ordering cause without proving the handler's precise execution time.

Display accepts a valid App Present independently of viewport visibility. A
hidden Present ACK proves the actual capability/source operation; it makes no
claim that the user saw App pixels. Hello's genuine Note completion, render,
Display Present ACK and startup Critical can therefore precede AppRunning UI.

## Decision

For only the actual required downloaded subject in Managed probation/join,
retain one cosmetic completion instead of immediately issuing AppStarted or
AppRestored to Shell. Root supplies and retains the complete admission binding:
actual PID/TID, full control capability, checked downloaded source, package and
App epoch. No binding is parsed from the eight-byte EVGADON1 event. Repeated
completion retains one notice. Stale binding, fault, stop, replacement, blocked
state or recovery debt discards it. Ordinary standalone completion is unchanged.

Release requires the existing real durable health commit, authenticated content
KnownGood publication and successful release of the same read-only health
session. The normal Root tick then rechecks the exact current binding and
actual actor liveness, reserves ordinary Shell outbox credit and consumes the
notice exactly once. Normal UI delivery and settlement remain in force. Shell's
existing AppRunning Present and real Input barrier then request an actual App
repaint. No synthetic input or frame is introduced.

The shared Host App-view gate requires a genuine App Present after the latest
actual Shell Present, exact current IDs, expected surface hashes, geometry and
grants, plus that Shell's actual protected Input barrier. Full captured scanout
pixels must match. A fresh-frame pixel mismatch fails; it is not retried.

## Preserved boundaries

Generic, Note client completion, actual App render/Display ACK, Critical, all
seven fresh LIVE checks and the actual durable Root probe remain mandatory.
No clock anchor,64-tick health window,512-tick child, whole-operation cut,
storage write fence, UI fence, capability, resource profile or quota is changed.
The pending notice grants no authority and is not health or visible-frame proof.
An unformatted or stale Note remains an honest refusal under existing guards.

## Verification and limits

A composed model uses authenticated B selection, saved Note and the same
read-only typed cache, real Note client response validation, actual graphics
render and compositor Present policy while hidden, then the real durable probe,
health/content KnownGood join and session release. It checks exact-once notice
release only after the join. Binding tests cover stale PID/TID/control/epoch,
wrong source, failure discard and ordinary AppStarted encoding. Host tests
reject cached App frames, absent or foreign barriers, changed IDs/hashes and
bad full pixels. These models do not measure actual startup timing.

Fresh exact source/product pins, all three actual Kernel/Root resource censuses
and an independently approved finite VM experiment remain required. Retain all
older failed runs without changing their classifications. Reconsider the
pipeline if actual Note/Present still cannot complete within the original cut;
never compensate with a renewed deadline or fabricated Critical.

## Bounded source-event responsiveness proposal

A later retained notice02 experiment removed the early Shell AppRunning debt,
yet B still missed the original64 window: Note request at anchor+36, next Root
LIVE at+68, no App Critical. Exact Note handler entry was unmeasured. Root's
four-receive/one-dispatch loop and outbound-before-dispatch ordering can delay
either incoming work or its real retained reply across turns.

A new isolated draft retains four protected receives and one actual outbound
attempt per turn. It dispatches at most four staged events, stopping after the
first potentially blocking handler. Only exact actor-role Ready, startup
Critical and AppDone tokens are local; ND, NT, owner/UI, NIC and unknown events
conservatively stop the drain. Existing current actor/control/UI/liveness and
per-event credit guards run before every handler. A handler returns its affine
backend and closes its output reservation before another can run; no recursive
or intra-I/O pump exists. Settlement debt stops the turn budget without reopening.
The single normal outbound attempt then handles existing or newly retained
responses in unchanged per-peer FIFO/alternating order before actual health
evaluation. A retained old Note body/ticket remains ahead of a new Busy reply.
Every progress check still uses its actual current clock. No input arrival time,
synthetic Critical, extra send attempt, accepted retry, deadline or quota change
is introduced. Models and fresh censuses cannot establish actual startup timing.

## Ready producer-output backpressure

The retained pipeline02 experiment failed before B download: ordinary A's Note
request11890 was accepted12725, while Activate reported refusal. The source can
queue a512-cut Shell control at AppDone then enter a possibly835-tick Note Store
handler before attempting that control. Exact outbox ticket expiry was not
traced. Shell already queues ControlSettled before automatic Repaint; changing
that order would be a no-op for these exact inputs.

The next private revision closes the staged-dispatch budget whenever actual
ready outbox output exists. This is Outbox::pending, excluding ingress and
unused reservation credit. The same single outbound attempt precedes another
handler; accepted controls retain their real UI settlement debt. Managed
AppDone only retains its cosmetic notice and publishes no output, so Generic,
Done and the typed cached Note read can still complete in the bounded turn.
No input readiness, peer-failure latch, body ownership, deadline or FIFO changes.

If output remains after that one attempt, ordinary native owner, transition,
UART and new network/update work waits via native_progress_only. Required
current-clock System work remains an explicit exception: admission/beginning,
join, stop/fault, probation decision and diagnostic snapshots keep their
original authority and cuts. In particular MissingProgress is not postponed
beyond64. This policy does not assert that all Store I/O is impossible under
queued output; the required System path may persist an honest failure or
complete its existing bounded phase. Models cover a512-cut control attempted
before835-tick ordinary Store work, preexisting output versus reservation,
no accepted replay, the same Managed cached-read path, and actual durable
MissingProgress persistence while output still awaits its normal attempt.

## Coherent first frame for sustained startup-health Hello

The retained03 experiment delivered the genuine saved Note at anchor+50 and
produced a second App Present whose authenticated surface hash matches Saved
M6 keep42. No App Critical was observed before Root's next LIVE at+70, beyond64.
That is progress in real data delivery, not health success or measured handler
entry/Present-ACK timing.

Only startup-health with stop0 now omits the redundant empty/loading initial
render after scalar read and GenericReady. It immediately starts the real NT
Read and stays in the ordinary receive loop. The existing reply handler still
validates protected nonce/body/AppId, loads the editor, performs the first
saved-data render and actual Present roundtrip, sends AppDone, then Critical.
Root Note/cache guards require actual admission but no prior AppDone/Present.
Normal and finite sessions retain their initial rendering; C's entry UD2 is
unchanged. The tradeoff is a short wait for one coherent first saved-data frame
instead of a loading flash. Refused/invalid reads render Unavailable and cannot
emit Critical; original client and Root deadlines remain unchanged.

Models exercise Note before any AppDone/Present, first saved frame1, genuine
health/probe/content joins, and malformed/foreign/refused/late first-read cases.
Source-order proof and unchanged default/C actual ELF checks accompany fresh
full-source three-mode and separate B/C production. These are not actual VM
startup timing or visible-pixel qualification.

## Promotion notice uses its caller's existing credit

Source audit found an unreachable post-promotion path: ordinary Root tick
already owns delivery_begin([1,1]) around native_tick, so the notice helper's
nested begin([0,1]) always returned Batch. No prior actual run reached that
publication. The helper now requires and uses the existing outer Shell credit,
without an inner begin/end. It still rederives the exact current Subject,
rechecks actual App liveness and consumes the released notice exactly once.
If credit is absent, valid pending metadata is retained; stale identity and
failure still discard it. Only the caller ends fanout reservations.

The helper returns true only after publishing the normal Shell control, and
native_tick then returns before ordinary work can consume its original512 cut.
No extra SEND, refreshed accepted operation or authority is added. A real
Outbox model reproduces nested Batch refusal, publishes through the same outer
ticket, and checks no-credit retention, stale-scope drop and exactly-once output.
