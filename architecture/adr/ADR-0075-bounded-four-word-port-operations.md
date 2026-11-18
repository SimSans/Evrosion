# ADR-0075 — Bounded four-word port operations

Status: Accepted Internal mechanism; actual controlled guest qualification pending

Date: 2026-11-12

Decision level: B

## Context

A ready ATA sector read executes at least543 scalar calls in `AtaPio::read_sector`,
including256 monotonic checks and256 Word inputs. Session admission and the
separate idle check add4 calls. The actual controlled09 and10 guests reduce
Kernel queue-maintenance overhead but still expire the unchanged8,192-tick
first GUI installation. Controlled10 reaches the Registry's first empty payload
write, without publishing a usable Registry head or install record. Its actual
Data Store retains1001; that partial result is not installation or session success.

Repeated device-port authority checks and trap transitions can be amortized
without giving the Kernel ATA, Store, package or application policy. Do not
extend the storage deadline or increase CPU credits to conceal this cost.

## Decision

Add a separate Internal port-word-batch v1 extension:

| Number | Operation | Four scalar operands | Result |
| --- | --- | --- | --- |
|46|`PORT_BATCH_INFO`|all zero|exact descriptor `0x0000000100040002`|
|47|`PORT_INPUT_WORDS4`|IoPorts capability, port, absolute deadline, zero|four LE u16 words packed in RSI|
|48|`PORT_OUTPUT_WORDS4`|IoPorts capability, port, absolute deadline, four packed LE u16 words|zero success value|

Width2 and count4 are fixed by opcode. Both repeated operations use the same
port, not an unchecked range or user pointer. All extra result fields RDX/R10
are cleared. Existing scalar35/36 semantics and original bootstrap ABI hashes
remain unchanged. The separate description identity is
`43efedc0506d458fd1003bca8bccc0e0f1263aeaa2585005e4c3b5f90e47906d`.
This hash identifies the source-defined extension; it is not publisher authentication.

The actual `native-session` Block actor must obtain the exact INFO descriptor
before reset, identify or any PIO. An older Kernel rejects the unknown INFO
operation before device I/O. There is no silent fallback under a relabelled ABI.
Finite Block profiles retain their existing scalar word loops and goldens.

## Authority, time and uncertainty

Before the first I/O instruction, the Kernel derives the actual running thread
and its registered Rpc domain from Scheduler/Rpc. The existing IoPorts registry
checks the live full-generation capability, exact object binding, READ or WRITE,
immutable direction and a Word transaction fitting the assigned port range.
Only a successful check can create the borrowed non-cloneable four-word permit.

The explicit deadline must be finite, strictly after the actual syscall capture
tick, and no more than1,024 ticks ahead. Malformed shape, wrong authority,
expired cut and overlong cut execute no I/O. The privileged boundary performs
at most four16-bit instructions at IF0 while retaining that exact permit. The
capture check is not a claim of an interruptible check between those four
instructions, calibrated wall-clock time, or an atomic device transaction.

Rpc cancellation does not revoke the still-live device owner's port capability.
An old expired cut refuses; the existing separately bounded cleanup cut may
permit reset/identify while the original request remains uncertain. Source
`SessionDisk` still derives cleanup from the original deadline plus its existing
1,024-tick grace. Actual stop or revocation denies further owner execution or
authority. A permit is not an ACK, device quiescence, durable completion, buffer
release or permission to replay the original operation.

`AtaPio` checks its original Budget before each group of four words. Its actual
session adapter uses the new trap; scalar/model adapters retain bounded default
helpers. Little-endian packing preserves sector bytes. A failure after a prefix
remains `MayHaveExecuted`; read data is published only after complete command
and idle verification. Reset/re-identification never claims write rollback.
Profile counters count each new operation as one port syscall; actual IRQ CPU
charges are unchanged.

## Validation and remaining gates

438 Core tests and48 session Block tests pass. New tests cover exact decoder
shape and separate description hash, finite/future deadline limits, Word range
and direction, attenuation/revocation, stale generation, actual scheduler exit,
and expired Rpc work versus a still-authorized owner's bounded cleanup. Actual
ATA algorithms run against the existing fake device: exactly64 groups transfer
256 words in the correct order, a crossed read cut publishes nothing, and a
partial write remains uncertain without rollback or replay. The older finite
Block suite also remains required.

The ready/no-Busy source-derived minimum falls from547 to163 scalar calls per
session sector read. This is a code count, not measured guest latency. Strict
target checks and the separately pinned controlled11 guest must qualify the
actual implementation, stack, per-sector cost and partial/full install outcome.
The known GUI install-to-Activate correction remains excluded from that causal
probe. Full current-source GUI, cold Note reopen, hostile isolation and M6
acceptance are separate gates.

Retained controlled10:
the local engineering archive.

## 2026-11-13 clarification: finite Native producer selection

The earlier statement that finite profiles retain scalar loops describes the
then-current producer selection. It is refined for the finite Native producer:
its Block recipe explicitly selects `native-driver,pio-word4`. Other finite
scalar profiles retain their existing selection. This is a Level B refinement
of the existing mechanism, independent of renewable CPU or session policy.

`pio-word4` requires `native-driver`, which selects the desktop driver entry
path and its mandatory exact INFO negotiation before reset, identify or any
PIO. `native-session` implies the same PIO feature. Selecting batching alone
does not select session duration zero, CPU windows, SessionDisk, cleanup or
quarantine policy. There is no fallback after negotiation or batch refusal.
Core operations47/48, their fixed four same-port Word instructions, live port
authority checks and the separate ABI description/hash above are unchanged.

Before each **new** four-word trap, ATA reserves four original poll units and
captures the clock once. Its child cut is
`min(original_ATA_deadline, captured_now.checked_add(1024)?)`; overflow or the
reserved maximum sentinel refuses. The original ATA/RPC deadline and remaining
poll budget are retained across all groups. Exact expiry, reversed clock or
insufficient poll credit refuses before PIO. Each accepted trap executes once;
there is no retry or renewal of an accepted trap. The physical work bound is
not increased by counting four words as one syscall. Original finite CPU,
world, health and operation limits are unchanged.

The uncertainty statement remains: a prefix failure is `MayHaveExecuted`,
latches `NeedsReset`, and does not authorize replay. A failed packed read is
not copied into the private sector buffer or published by the finite driver.
For precision, the unchanged finite driver publishes a complete sector after
`read_sector` has completed its ATA idle verification, then performs an extra
idle check before ACK. Failure of that extra check can leave the complete
sector in the shared window without an ACK; it is not a reusable-buffer or
completion receipt. SessionDisk separately retains its existing publication
after its additional idle check. Neither path claims write rollback.

The separately pinned preparation includes scalar/PIO/finite/session/network
models, actual compiler feature-selection checks, strict bare Block and Host
checks, and the original finite budgets. These are preparation results, not an
A/B outcome, physical CPU-time measurement, performance qualification or M6
acceptance. The original failed finite NativeSystem evidence remains failed.
Any actual A/B outcome requires its own closed source/artifact/process record.
