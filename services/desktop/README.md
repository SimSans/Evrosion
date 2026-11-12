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
See [M4 progress](../../docs/release/0.1-preview.md#validation-and-provenance) and
[ADR-0046](../../architecture/adr/ADR-0046-owned-surfaces-and-userspace-display.md).
