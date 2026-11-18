# Reference Input core

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

The explicit `native-session` service opts into `Stream::with_pointer()`;
the default finite profile remains action-key only. The session stream shares
one pending credit and one nonwrapping sequence among keys, printable text and
complete pointer packets. A barrier discards pending output while consuming real
bytes through the same keyboard/text/pointer decoders, retaining modifier and
button state. A partial pointer packet cannot cross a successful drain.

Before its first poll/drain, `Driver::enable_mouse()` performs one cold reset:
the actual AUX replies must be `FA AA 00`, establishing the three-byte format,
followed by an acknowledged `F4`. QEMU10.2.1 `F6` resets defaults without resetting
the negotiated mouse type; it is deliberately insufficient. IRQ1/12 stay masked,
and initialization never expands the port claim beyond `0x60`/`0x64`. A running
Input cannot call this cold path to satisfy a UI barrier.

`SessionBarrierRequest` is `KBR2` plus the diagnostic nonce. Its eight-byte reply
is `['B',2,enterFlags,pointerFlags,sequenceLE32]`: pointer bits0..2 are actual held
buttons, bits3..5 record releases observed in complete actual packets, and high
bits are zero. Initial/reset/quiet state alone establishes no button release.
Legacy `KBR1`/`B1` requests, replies and golden bytes remain unchanged.

`pointer::FreshGate` is armed only after actual trusted UI Present and the
authenticated session barrier. A held or release-unknown button needs a real
release followed by a new post-barrier make. Pointer clicks never become Enter
events. Shell forwards absolute logical positions as `PositionEvent`: `M`,
`0x20|buttons|(xHigh<<3)|(freshLeftPress<<4)`, `xLow`, `y`, `sequenceLE32`.
Coordinates are bounded to320x200; a fresh press must also report left held.
This explicit trusted-Shell freshness result avoids inventing a down edge when
an App missed pointer movement/releases while obscured. The actual fixed Shell
sender and current App admission remain mandatory; these bytes grant no focus,
File authority or durable consent by themselves. Integrated manual VM acceptance
is separate from the decoder/controller and policy tests.
