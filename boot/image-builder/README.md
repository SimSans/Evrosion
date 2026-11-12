# Boot image builder

Host backend for the x86_64 UEFI image, using bootloader 0.11.17 under
[EXC-0001](../../architecture/exceptions/EXC-0001-temporary-bootloader.md).
Invoke it through `cargo ev build`. It embeds the unstripped kernel in the
upstream FAT/GPT image and exports the exact embedded EFI loader for hashing.

The upstream crate's build script runs a nested cargo install of
bootloader-x86_64-uefi 0.11.17 with --locked and rebuilds core for UEFI. Its
published lockfile is preserved at third_party/bootloader-uefi.Cargo.lock and
inventoried separately. A cold build needs network access; cargo fetch of the
workspace alone does not prepare this second dependency graph.

The output is unsigned. Upstream image identifiers and timestamps have not yet
been normalized, so byte-identical image acceptance remains Slice 5 work.
