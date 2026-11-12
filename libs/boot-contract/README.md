# Boot contract adapter

The no_std adapter for the temporary bootloader_api 0.11.17 handoff. Its entry
macro contains the external glue; kernel code receives Evrosion BootInfoV0.
The library copies and sorts at most 512 regions, reserves unknown memory kinds,
rejects overlaps/invalid arithmetic, checks kernel ranges, and validates optional
framebuffer dimensions, stride, format, size and canonical virtual addresses.

Framebuffer absence is valid. Boot generation and command line are explicitly
absent for this backend. The physical kernel range identifies the loaded ELF
bytes; the virtual range comes from linker bounds, not the ELF file length.
This is an Internal Rust structure, not a stable binary ABI.

The loader is trusted to provide valid Rust references and mapped buffers.
Validation establishes metadata consistency; it cannot authenticate arbitrary
raw pointers. Host tests cover valid and malformed handoffs and framebuffer
layouts with `cargo test -p ev-boot-contract --locked --offline`.

See [EXC-0001](../../architecture/exceptions/EXC-0001-temporary-bootloader.md)
and [M0 requirements](../../architecture/plans/roadmap/PRE-M0-implementation-package-v1.md).
