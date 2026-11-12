# Reference keyboard Input core

Safe `no_std`/no-allocation set1 decoding, strict eight-byte freshness frames,
one pending key and bounded userspace PS/2 controller initialization. The actual
service is [input.rs](../../services/desktop/src/input.rs). Physical acceptance
remains pending its integrated VM proof; portable/controller-model tests do not
prove real input, focus, trusted widget provenance or user consent.

Input alone receives the scoped byte ports `0x60`/`0x64` with READ|WRITE, Shell
key SEND, Root event SEND and its own control RECEIVE|CONTROL. It configures the
keyboard in userspace, without PIC, network or other device authority. On the
reference QEMU10.2.1 backend it disables AUX/translation/keyboard interrupt bits,
selects and queries raw scan-set1, validates ACK/RESEND and enables scanning.
These command/status behaviors were checked against the matching primary
[PS/2 implementation](https://github.com/qemu/qemu/blob/v10.2.1/hw/input/ps2.c)
and [i8042 implementation](https://github.com/qemu/qemu/blob/v10.2.1/hw/input/pckbd.c).
All polls share an absolute operation deadline and finite budget. A drain
requires two quiet ticks, covering the reference controller's1ms throttle, and
rejects an incomplete prefix. Hardware errors, wrong encoding/configuration,
clock reversal/stall, unsupported replies and counter exhaustion fail closed.
There is no automatic reset/retry that forgets a running keyboard's held state.

`KeyEvent` is exactly `['K',1,key,flags,sequenceLE32]`, with key1Tab/2Enter/
3Escape/4Up/5Down. Only distinct MAKE events get nonzero nonwrapping sequence
values; MAX is refused. Non-Enter flags are zero. Enter bit0 means this physical
main/keypad key has a real validated break since initialization; bit1 means an
eligible fresh make, requiring bit0 and release of every Enter held at the most
recent barrier. Impossible/unknown flag combinations, tags, versions and keys
are refused. Main and keypad Enter have independent held/release state.

`BarrierRequest` is `KBR1` plus a LE32 diagnostic nonce (zero allowed, MAX
refused). Actual request/reply identity comes from the protected kernel CallId
and reply nonce, not these bytes. `BarrierReply` is `['B',1,flags,0,sequenceLE32]`;
flags main-release-known1/keypad-release-known2/main-held4/keypad-held8, high bits
zero. Malformed requests return `KBE1` plus error1 under the actual reply lease.

The source loop checks control before each pending-key retry. A barrier drops
the one unsent key and drains real controller bytes through the SAME decoder,
updating physical state and sequence while forwarding none. Held keys are pinned
again at the final reply cut, including makes that arrived during the drain.
Queued Shell frames at or below the returned sequence are discarded. Unknown
startup-held Enter may perform benign Launch/OpenFile, but cannot approve until
a real break followed by a fresh make. Repeats cannot turn into approval by
resetting the decoder, and a release of keypad Enter cannot release main Enter.

`FreshGate` is a pure metadata reducer for the Shell AFTER actual trusted UI
Present acknowledgement and an authenticated Input barrier RPC. It filters old,
duplicate, unknown-release or held Enter events; its structs/flags are never
capabilities or consent. Only the actual Input-source channel may feed it. Root
and Shell must cancel pending approvals when Input dies/restarts; runtime
handles or sequence counters must not be persisted as grant policy. Stable
object/version/requester checks and actual selected-file capability delivery
remain separate requirements.

Full output queues retain exactly one pending frame until canonical SEND
acceptance; no extra hardware bytes are consumed while it is pending. Controller
drains for barriers still run first and explicitly discard it. Any Input failure
refuses the operation and requires supervised lifetime handling, rather than
claiming device repair, focus or successful approval.
