# ADR-0076 — Bounded network stop continuation

Status: Accepted Internal mechanism; controlled guest qualification pending

Date: 2026-11-12

Decision level: B

## Context

Controlled network08 completed actual DHCP, DNS, TCP, the exact57-byte HTTP
request and the exact28-byte fixture body. The owner runner then sent its real
`finish` command. The legacy Driver Stop5 attempted the full16KiB zero/write
and physical readback in one inherited1,024-tick RPC and expired. Actual Driver
NE classified Stop/DeviceDeadline, Service NE retained its remote failure, and
Root emitted NW8 at shutdown. No NW7, NIC quiescence or full retirement was
proved. The original240-second run and immutable bytes remain a failed whole
gate; the HTTP subgate is independently valid.

A bulk scrub has128 bounded pieces. Making those pieces explicit avoids one
long protected call and does not require more CPU credits, a larger stack,
renewing a timed-out operation, or claiming CPU exit stops the physical NIC.

## Decision

Keep every existing N1 Driver and S1 Root-control opcode and wire encoding,
including Driver Stop5 and Service Shutdown9. Add strictly versioned operations:

| Route | Request | Body | Joined result |
| --- | --- | --- | --- |
| N2 | StopBegin6 | one immutable LE u64 aggregate cut | Progress7, cursor0 |
| N2 | StopStep7 | empty | Progress7, or final Complete0 |
| S2 | ShutdownBegin10 | the same immutable LE u64 aggregate cut | Pending1 |
| S2 | ShutdownStep11 | empty | Pending1, or final Complete0 |

Version is derived from opcode in both scalar notice and shared frame; wrong
version/opcode combinations refuse before device I/O. Old peers cannot silently
run new semantics. The additive V4 ABI description explicitly binds this
contract; it does not relabel the older bootstrap or reinterpret old operations.

The Driver result body is exactly8 bytes: done LE u16, total16,384 LE u16,
chunk128 LE u16, reserved zero LE u16. Cursor increments exactly128 per newly
accepted Step; Complete is canonical only at16,384. Root counts the exact128
joined Step acknowledgements independently. Intermediate Progress/Pending is
neither permission to reuse the NIC nor a hardware-quiescence proof.

## Ownership, bounds and uncertainty

Root captures one new8,192-tick cleanup transaction at explicit owner finish.
The Root state retains that exact cut and cannot restart or renew it. Each new
Root RPC has a finite child cut no more than1,024 ticks ahead, clamped to that
aggregate. Service forwards the exact Begin body and uses a child no more than
512 ticks ahead, clamped to both the inherited RPC cut and original aggregate.
The original HTTP transaction remains independently bounded by its old8,192
cut and128-work cap. No deadline or CPU quota for ordinary work changes.

Service latches terminal before invoking Driver Begin. Normal stack pumping,
TX and RX cannot resume during cleanup or after an uncertain result. Driver
Begin asserts and verifies STOP, restores and reads back the full packet-RAM
wrap bounds in byte mode, and captures cursor0. Each Step verifies STOP and
bounds, writes exactly128 zeros at the next physical packet-RAM address,
physically reads back exactly those128 bytes, then verifies STOP/bounds and
its original child cut again. Remote DMA keeps STOP asserted; no reset, START,
normal packet pump, or synthetic padding is used. Only that last verification
advances the cursor. Final Complete requires all16KiB plus fresh STOP.

A partial transfer, corrupt readback, expired/regressed clock, transport error,
unknown accepted result, or noncanonical cursor quarantines the owner. No
accepted operation is replayed and no failed cursor is advanced. The original
shared window and actual hardware debt remain retained. Diagnostic expiry
still drops only its observation. Only final actual Driver completion joined
through Service may clear Root hardware debt; real CPU Stop/Reap and Kernel
memory/authority cleanup still follow and remain separately checked.

## Validation and remaining gates

Meaningful device-model tests dirty all16KiB, verify each exact zeroed prefix
and untouched suffix, prohibit RESET/START, and require exactly16KiB written
and physically read. Negative tests cover bounds tampering, corrupt readback,
pre-expired/overlong children, clock regression, Step before Begin and duplicate
Begin without extra I/O. Protocol goldens retain every old N1/S1 notice and
reject wrong-version frames. Client/service models check strict cursor progress,
lost acknowledgements, terminal/no-pump behavior, unknown-result pinning and
nonrenewable aggregate cuts. Focused and strict target results will be retained
with the controlled09 source and actual selected Kernel stack census.

Controlled09 must derive exact network08 plus only this continuation contract,
not unrelated Main dynamic-image, Time-client or capacity changes. It uses the
original240-second host bound, unchanged HTTP caps and CPU credits, and a fresh
source-bound producer/census before the actual probe. Source models alone do
not prove physical quiescence, packet delivery, full retirement or M6 completion.

Retained actual08 audit:
the local engineering archive.
Its original runner postflight contained a metadata-key collision; the unchanged
source/artifact closure is independently verified by the append-only
`postflight-supplement.json`. Neither record relabels the failed run as success.

## Refinement: four-byte scrub groups under the same cuts

Actual controlled09 reached NW7, then exposed a separate legacy-six-slot Kernel
collector bug before full cleanup. The exact controlled10 collector correction
keeps every retirement/registry/scheduler guard, but its next actual NIC cleanup
expires the same8,192 aggregate. That is an observed failure, not permission to
extend the cut or CPU quota. Both original runs and their partial scopes remain
retained. The actual09 Driver profile records4,079 charged CPU ticks including
startup,37,099 byte inputs and37,935 byte outputs. Existing per-byte monotonic
checks add a separate trap to every byte of each physical16KiB zero/readback.
With the unchanged64/256 child window, that overhead leaves insufficient margin.

Refine only the new StopStep's known-STOP packet-RAM data loops. Each group
performs at most four byte-port operations at the fixed data port. It checks the
original clock and poll budget before the group, counts every physical step,
keeps the existing yield/check at each64-step boundary, and checks the clock
again after the group. Register setup, STOP/bounds checks, physical readback,
total16KiB coverage,128B cursor geometry and final checks remain unchanged.
Legacy Stop5 and normal TX/RX still check every byte exactly as before. N2/S2
wire encodings and the captured original8,192/1,024/512 cuts do not change.

A preemption after a pregroup check can allow at most four fixed stopped-RAM
data operations after expiry. It cannot transmit, resume a normal packet pump,
escape the fixed byte port, extend the aggregate, advance progress, ACK success
or release an owner. Expiry/regression at the mandatory postgroup/final check
quarantines the original cursor and retains every unresolved device/window debt.
This explicitly bounded uncertainty is preferable to thousands of redundant
clock traps in an already stopped bulk scrub. Every ordinary port operation
still passes its real Kernel capability and running-owner authorization.

The actual device-model tests inject expiry, regression and partial I/O after
each of the four possible positions in both write and read groups. They require
no more than three later data operations, no cursor advancement, no retry, no
RESET/START and no writes outside the current128B packet-RAM chunk. Readback
corruption remains refused. Another test counts exactly128 physical writes and
128 reads and retains64-step yielding while reducing clock queries. Controlled11
must qualify this exact device/test/ADR-only refinement on controlled10, with
fresh actual producer/census and the original full probe gates.
