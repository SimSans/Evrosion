# Test protocol

Shared no_std constants for M0 serial protocol version 1, exact entry/result
markers, and the QEMU exit port/value/status convention. It remains Internal.

The kernel writes 0x10 to port 0xf4 on success, producing host status 33. Failure
uses 0x11/status 35. The host parser in tools/ev/src/boot_protocol.rs additionally
requires ordered, unique records, valid framebuffer fields, the expected build
ID, the exact entry marker and final PASS, with no panic/failure or trailing data.

The protocol is specified in the [Pre-M0 package](../../architecture/plans/roadmap/PRE-M0-implementation-package-v1.md).
