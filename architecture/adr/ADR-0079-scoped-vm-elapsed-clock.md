# ADR-0079 — Scoped VM elapsed clock and read-only RTC

Status: Accepted Level B implementation refinement; actual selected Kernel and guest qualification pending.
Date: 2026-11-12.

## Decision and scope

The explicit reviewed developer Network VM profile uses a private, source-bound
Linux/x86-64 clock module and a Root-only read-only calendar adapter. This
provides a candidate coarse elapsed source for subsequent signed-time work.
It does not qualify UTC, a minimum elapsed rate, generic physical hardware,
arbitrary QEMU builds or an untrusted owner host. Kernel PIT scheduling and all
operation/health/owner deadlines remain independent and unchanged.

The trusted owner host, compiler, dynamic loader and reviewed QEMU remain
assumptions. Hashes and CPUID cannot attest a hostile host. The selected actual
QEMU executable and closed arguments must match the independently reviewed
source profile. The launcher removes all ambient `LD_*`, `GLIBC_TUNABLES` and
`QEMU_PLUGIN` inputs, then supplies only its exact privately compiled module.
Compiler inputs, source/module/compiler/QEMU identities and actual command are
retained and freshly checked. No host clock or process-global environment is
written. Paths using whitespace/colon preload-list grammar refuse.

The primary `tools/m6/clock_boottime.c` is copied only when its bytes match the
frontend's embedded source. Its imported `clock_gettime(CLOCK_MONOTONIC)` uses
`CLOCK_BOOTTIME`; other clock IDs retain their raw syscall semantics. A missing
BOOTTIME source exits125, including during construction, with no gettimeofday
or deterministic fallback. The private0600 audit file is new, no-follow, regular,
single-linked and owner checked. A bounded32-record audit includes construction
and the actual reviewed imported MONOTONIC-to-BOOTTIME QEMU callsite. Constructor
success alone never authorizes release. Concurrent publication uses atomic
acquire/release; audit sequences are unique but need not be written in order.

QEMU starts halted with `-S` and exact
`-rtc base=utc,clock=rt,driftfix=none`. Before any guest execution, the owner
verifies the actual process's executable module mapping, inode/device/path,
non-writable executable extent, reviewed imported caller and audit. QMP must
report prelaunch/nonrunning, acknowledge `cont`, then report running. Source and
module identities are checked again after execution. Compiler and prelaunch
waits are finite. Failure retains evidence and the owned child is stopped/reaped;
there is no unqualified launch fallback. UTC-provider qualification remains false.

## Root authority and calendar protocol

V4 appends selector29 `RtcPorts`, IoPorts kind7, exact READ|WRITE rights3. It has
no DERIVE/TRANSFER/CONTROL grant and is absent from every child's startup graph.
The actual Kernel registry narrows it further to byte index70 Output and byte
data71 Input. RTC data writes, index reads, adjacent ports and wider operations
refuse even with the Root read/write capability. Existing generic port permits
still revalidate actual running process, domain and live capability. No new
syscall, ambient device access, actor, mapping or RAM frame is added.

The Root adapter writes only allowed calendar selectors, never data. The reviewed
Q35 model ignores index bit7; this is explicitly not a physical NMI-mask policy.
Each read captures one original512-PIT-tick cut and permits at most4 snapshots,
with at most8 UIP polls each. It requires two consecutive equal snapshots,
consistent mode flags, running divider, SET clear and source-valid status.
BCD/binary and12/24h conversions validate every digit and Gregorian date,
including century/leap rules. RegisterD validity is not UTC-quality evidence.

Only elapsed whole seconds relative to the actual first observation are exposed.
Backward PIT/calendar observations, unavailable ports, inconsistent snapshots,
invalid calendar/configuration, reached original cuts and overflow fence this
Root-incarnation source; stale samples or PIT/host-UTC substitutes never satisfy
a security-time read. One-second floor quantization is explicit. A fresh private
CSPRNG-derived domain is created after actual random-source qualification; the
repeating prototype catalogue epoch is not a cross-boot time identity. A failed
security-time source may remain unavailable while local UI and PIT still work.

`Root::native_elapsed` samples actual ports for later publication/verification
brackets. Ordinary network ticks also sample every1024 PIT ticks; PIT only schedules
these observations and supplies no conversion to seconds. At most16 sampled
`TM` diagnostics are queued on authenticated RootEvents: initial1/sample2/failed3,
result success0/unavailable1/regression2/bounds-or-protocol3 and elapsedSecondsLE32.
No date, seed or UTC-quality label is sent. Operational source high-water checks
continue beyond the diagnostic cap. One retained8-byte frame uses its original
local4096-tick preaccept cut and one ordinary-tick SEND attempt; canonical Busy
retains it. Successful scalar SEND consumes once even if preemption crossed the
local cut: this ABI supplies no Kernel-atomic caller acceptance deadline.
Diagnostics never establish time trust or device quiescence.

Startup remains912bytes/max32 slots; FullGraph now requires exact29 roles and
manifest1136bytes. Catalogue4096 and layout1024 remain fixed. Layout roles end848;
job templates move to848..944, capacity944..976 and `EVRTC004` binds976..1024.
The V4 ABI binds this profile. Service/v1, Desktop/v2 and Native3 bytes stay strict
and unchanged; no legacy validated object is converted into a V4 token.

## Measured bounded V4 image refinement

The prior resident-Controller baseline retained103 image pages/109 private frames
and23,128/32,768 bytes in the linked resolved-reference stack census. The first
joined RTC candidate correctly refuses the previous104/110 bound:105 PT_LOAD
pages (87text,7ro,3rw,8declared stack),111 private frames. Its ELF SHA256 is
`ddd0570c7590c4a6285d88920399d3a20a448af367b672d13c0a1c48735e9d2c`;
resolved stack is23,144/32,768. This is joined source, not a controlled RTC-only
size comparison. A small shared-conversion/out-of-line experiment grew to106/112
and was retained then reverted; checks were preserved rather than weakened.
Original artifacts from both experiments are retained in the local engineering archive.

Permit only the exact verified V4 Root at most108 image pages,112 owner slots and
114 loader-owned private frames. This supersedes ADR0077's104/108/110 ceiling for
the measured RTC staging requirement, not an allowance for unmeasured crypto.
Existing single-source SDK/Core aliases and selected outer Root owner carry the
limit; ordinary actors remain64/68 and Native3 remains96/100/102. Existing actor
array sizes, Root512 frame quota, CPU charging, permissions, lifetime,32KiB Root
stack and256KiB Kernel stack remain unchanged. A109-page actual V4 image refuses;
wrong-profile/legacy constructors never acquire the larger ceiling.

## Verification and remaining gates

Focused tests use the exact primary C in real bounded subprocesses, including
source failure before/after construction, exit125/no fallback, existing/symlink
refusal, source/module mutation, audit replay/truncation and exact imported-map
checks. QMP tests exercise actual transport framing and wrong start/ACK/status
states. Portable tests exercise calendar coherence, invalid Gregorian data,
original-cut expiry, rollback and permanent fencing, actual port direction/domain
refusals, V4 authority/layout/ABI binding and unchanged legacy byte fixtures.
Capacity tests load exact verified V4 manifests through108 pages, refuse109,
retain all112 mapping claims on refusal and reclaim once. These tests and linked
reference censuses are not actual guest, runtime high-water or whole-M6 proof.

Before a guest claim, the exact source-frozen eight-actor producer and selected
Kernel must pass their original image, mapping and256KiB stack preflights after
the owner size change. Actual scoped RTC readback, host/VM pause and suspend
behavior, justified minimum rate, fresh signed time and durable-floor joins remain
separate obligations. The elapsed module or host clock label alone cannot provide
UTC or authorize release metadata. Refuse at any failed bound; no automatic
stack/quota increase or silent profile fallback is permitted.

## Conditional signed-time client staging

The next actual Root client uses `ClockModel::one_second_floor(1,2)` with immutable
exchange30seconds, anchor60seconds, future window1second and signed radius at
most10seconds. The model is explicitly conditional: the trusted healthy Linux
host/kernel, selected clocksource, privileged clock administration and correct
suspend accounting must preserve at least one half elapsed clock second per UTC
second. This wide margin is a declared developer-profile TCB assumption, not a
bound inferred from SNTP, a synchronized flag, `adjtimex` tolerance or benchmarks.
It grants no authority while actual provider qualification remains absent.

The read-only current host snapshot has Linux7.0.0-42-generic, clocksource `tsc`,
constant/nonstop-TSC flags and CONFIG_HZ1000. A modes0 `adjtimex` observation has
tick10000microseconds, frequency about+5.39ppm, STA_PLL|STA_NANO and tolerance
500ppm. Linux's installed timex header declares MAXFREQ500000ns/s. These are
configuration/source observations, not a complete minimum-rate proof: ADJ_TICK,
phase correction, oscillator calibration/failure and suspend accounting also
matter, and privileged configuration can change. A host outside the declared
healthy profile must leave security time unavailable. Suspend inclusion is the
BOOTTIME API contract, not an actual host-suspend measurement here; injected
sleep time and hardware health remain trusted. Actual VM pause/readback and
qualified whole-window evidence remain required. No ordinary wall/NTP label
supplies the absolute UTC interval.

The reviewed RTC reads update calendar data from
`base_rtc*1e9 + qemu_clock_get_ns(rtc_clock) - last_update + offset`, then divide
by1e9. Every calendar-data read updates this value while running. `clock=rt`
selects QEMU_CLOCK_REALTIME/get_clock, independently of guest virtual-time pause;
the exact imported MONOTONIC read is redirected to BOOTTIME. Consistent calendar
values identify actual coarse observations, not an atomic future persistence
decision. A fresh post-crypto observation and another fresh observation at the
later trust-publication boundary are necessary, covering the entire declared
window. No stopped PIT interval may stand in for that elapsed window.

A single optional Native-network time exchange follows successful independent
Hello transfer. The same retained Client505 owner initiates ordinary TCP close,
waits for actual Closed, then reconnects the same catalogue-scoped destination.
It captures one original8192-PIT-tick transport cut with child RPC cuts at most
1024ticks,128 calls and no accepted-unknown retry. A fresh RTC origin precedes
actual private qualified-Random output. A private one-shot source transfers that
one output into the affine TimeProof Client and erases its staging bytes on all
outcomes. No second generator, caller-chosen verification API, restored nonce,
ready-state cache or relay-selected key exists.

The public request is `/time/<64 lowercase hex nonce>` over the untrusted local
HTTP relay. The actual relay sends one UDP request to162.159.200.1:2003; routing
and DNS cannot replace the independently pinned provider key. A separate bounded
HTTP parser copies at most864 body bytes into private Root memory, permits at
most512 header bytes, rejects ambiguous/compressed/chunked framing and requires
exact Content-Length plus actual EOF. No shared-window reference survives a
protected call or enters the signature verifier.

Client.finish consumes the private challenge and verifies the pinned-key
signature/delegation/nonce path. Actual RTC reads after verification are checked
through Anchor.observe_post_crypto; no zero or fictitious committed floor is
passed to Anchor.window. The verified Anchor remains a private unqualified
candidate. There is no QualifiedWindow construction or durable trust publication
in this slice. A future publisher must obtain the actual committed floor and a
fresh current elapsed read, enforce whole-window limits and qualification, then
atomically commit the exact trust transaction. Cancelling the local challenge
never releases an unknown actual ClientWindow loan; that owner remains pinned.
