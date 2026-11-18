# ADR-0061 — Sequenced text and relative pointer data

Status: Accepted — portable contracts; actual Input/Shell integration pending
Date: 2026-11-12
Related: M6-02; E-017; E-025; A-004; A-011; ADR-0047/0048

## Decision

Add independent bounded set1 US-ASCII text and three-byte PS/2 pointer decoders
in `ev-input`, leaving the existing Keyboard, five action keys, Stream and
protected approval/barrier semantics unchanged. Introduce distinct eight-byte
Internal data frames so a text byte or pointer button cannot be reinterpreted
as an eligible Enter or proof of consent.

The actual Input owner will assign one nonwrapping sequence across action,
text and pointer events. These new codecs validate nonzero sequence values and
reject MAX; they do not mint sequence authority or authenticate a sender.
Receivers must bind the real protected Input channel/incarnation, reject replay
and cancel stale focus/actions on replacement. Values alone establish neither
focus, widget provenance, object authority nor owner approval.

## Text path

`text::Decoder::feed(status,data)` consumes bytes already established as set1 by
the actual controller driver. It produces printable US-ASCII or Backspace on
MAKE. BREAK emits no text. Ordinary typematic text repeats remain data; Caps Lock
toggles only on a distinct make/break. Independent left/right Shift and Ctrl/Alt
state prevents one physical alias from releasing the other. Caps XOR Shift
affects letters; Ctrl/Alt suppress text including Backspace. Enter, Tab, Escape
and navigation remain in the existing action-key path.

Full/short PrintScreen, SysRq and Pause/CtrlPause aliases are consumed without
turning fake Shift/Ctrl bytes into real modifier state. Parity/timeout,
unambiguous command replies, set2 prefixes and malformed/unfinished sequences
fail closed. State has no in-lifetime reset API. Controller initialization must
consume command responses and drain stale bytes before a new supervised Input
lifetime; ambiguous set1 BREAK bytes cannot safely be guessed to be replies.

`TextEvent` is `[b'T',1,character,0,sequenceLE32]`. Character is0x20–0x7e or8
for Backspace. Other control bytes, version/tag/reserved bytes and impossible
sequence values refuse. This is an initial US-ASCII developer contract, not the
global text/locale/IME architecture in A-011. Numeric keypad digits and layout
selection are not inferred from a guessed Num Lock/locale state.

## Relative pointer path

`pointer::Decoder::feed(status,data)` consumes only actual AUX bytes, preserving
a partial packet across interleaved keyboard bytes. It emits only after three
bytes with the required framing bit and no X/Y overflow. A malformed header,
controller error or partial packet at the drain/end cut latches failure rather
than guessing resynchronization. The caller must initialize and verify the
three-byte protocol; a wheel/four-byte mode cannot be silently parsed as three.

`PointerEvent` is `[b'P',rawStatus,rawX,rawY,sequenceLE32]`. The payload retains
signed nine-bit relative dx/dy and three button bits (left1/right2/middle4).
It has no absolute10-bit coordinate ceiling; the compositor accumulates and
bounds motion against its actual surface with checked arithmetic. Positive
PS/2 Y is upward. A future incompatible wire uses a distinct tag/contract.

The reviewed [QEMU v10.2.1 PS/2 source](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/input/ps2.c)
contains modifier-dependent PrintScreen/Pause aliases and three/four-byte mouse
modes. This supports the decoder's explicit framing choices, not an actual
device or whole Input initialization proof. Existing five-key runtime profiles
do not enable AUX merely because these new helpers exist.

## Integration and acceptance

The actual Input loop must retain one pending frame until canonical SEND
acceptance, give protected control/drain work priority and preserve the same
held-Enter knowledge. Do not reset the old approval decoder to recover text or
mouse state. Future pointer-click approval needs its own actual post-Present
mouse barrier/drain and held-button freshness; it cannot synthesize an eligible
Enter or borrow another key's release.

Portable tests cover complete printable mappings, aliases, modifier releases,
typematic/lock behavior, unknown replies, partial/restarted streams, malformed
frames, signed motion bounds, AUX interleaving and overflow. Actual i8042/AUX
configuration, real keyboard/mouse input, focus routing, backpressure, Input
replacement and readable Shell/App behavior remain M6-02 execution gates.
