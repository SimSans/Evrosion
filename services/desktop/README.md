# First source-built graphics actors

Separate App and Display executables use ordinary measured Registry admission.
App renders a 320x200 RAM surface and blocks on protected Present. Display maps
that surface READ-only and alone receives a guarded device aperture; it copies,
publishes stores with SFENCE, then replies. No kernel code paints pixels.

Negative variants attempt App framebuffer access and Display writes to the
READ-only RAM surface. The physical runner must observe actual contained faults,
not infer them from host tests. Both actors use guarded 16KiB private stacks.

This two-actor slice precedes the complete Root/Shell/Input/File/Block/App/Display
graph, real focus/input, trusted file grant and crash/relaunch M4 acceptance.
See M4 progress and
[ADR-0046](../../architecture/adr/ADR-0046-owned-surfaces-and-userspace-display.md).

The paragraph above describes the initial two-actor slice. The subsequent full
bounded graph passed M4 acceptance; later
native and connected controls are qualified by M6 readiness.
These reference proofs do not complete consumer window management, arbitrary
GPU support, the full responsibility-layer interface or accessibility providers.

The separate M8 `workspace-input` feature implies `input,native-session` and
selects a strict three-role V1 profile: PIO1, combined RootEvents2 for Ready and
raw physical stream events, and Root-only Barrier RX3. Its UI-independent raw
PointerEvent still carries relative signed motion and a full32-bit sequence;
Root owns640x480 absolute coordinates. Root must receive the shared event channel
through actual RECEIVE_EVENT39 and match both full Process and Thread to its
current live Input actor before treating bytes as physical input. A packet tag
or Ready instance alone is never source evidence. Legacy `input,native-session`
retains its exact four-role map and pointer/barrier wire bytes. This selected
Input image keeps the legacy guarded16KiB stack256..259 and32-frame Job template;
it does not select the new UI32KiB stack. Local host/link/stack receipts remain
separate from actual PS/2, grants, freshness, recovery and VM qualification.
