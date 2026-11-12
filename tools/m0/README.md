# M0 acceptance workflows

Use the Rust frontend: `cargo ev bootstrap`, `cargo ev test m0`,
`cargo ev image --verify-reproducible`, `cargo ev test architecture --milestone M0`.
Python orchestrates these fixed repository workflows and stores JSON/JUnit/logs
under new evidence directories; it does not rewrite historical evidence.

## Prepared Linux host

Install Git, Python 3.11+, a C linker, Rustup, QEMU x86, OVMF and GDB using your
distribution packages. On Ubuntu/Kubuntu the host packages are build-essential,
git, python3, qemu-system-x86, ovmf and gdb. Then clone the repository, run
`cargo ev bootstrap`, followed by `cargo ev build` and `cargo ev test boot`.
Rustup installs/verifies the exact repository pin and required components/targets.
The first Cargo invocation can install that pin automatically through Rustup.
Bootstrap verifies host dependencies and prints actionable fixes; it does not
run sudo. Cold builds fetch both the workspace and separately locked EFI graph.

## Debug and panic

`cargo ev debug kernel` starts QEMU paused (`-S`) and opens GDB with the exact
verified unstripped ELF. Use `continue` to hit evrosion_kernel_entry, `bt` for a
backtrace, then `detach` and `quit`. Its GDB listener binds loopback only.
`cargo ev debug kernel --batch` demonstrates the breakpoint, source line and
backtrace automatically and retains the transcript alongside serial evidence.

`cargo ev build --fixture panic` creates a separate image with a deliberate
panic. `cargo ev test panic` requires the correct build ID, source location,
bounded message, failure marker and QEMU exit 35. `cargo ev debug kernel --batch`
also stops at evrosion_deliberate_panic and records a source/backtrace before
resuming through the real panic handler. Restore with `cargo ev build`.

The no-framebuffer fixture exercises the kernel's serial-only branch with a
validated boot contract; host tests separately pass absent framebuffer metadata
through the real adapter. This is simulated absence, not hardware qualification.

## Reproducibility and scope

Commit a reviewed candidate before `cargo ev image --verify-reproducible`.
It makes two local Git clones with no build outputs, compiles kernel and EFI in
separate target directories, and compares complete unsigned images byte-for-byte.
It also compares kernel and EFI hashes. Registry sources and the pinned compiler
may be shared. Host-built helper executable paths/debug bytes are not an OS image
reproducibility claim. Fixed GUIDs are for development images only; FAT timestamps
use 1980-01-01 because FAT cannot represent SOURCE_DATE_EPOCH=0 (1970). EFI linking
disables CodeView/PDB metadata with `/debug:none`; kernel symbols remain intact.
The image-builder cache uses target/m0-image-v2 to avoid reusing older EFI media.

Evidence remains local under ignored build/. The m0-first-pass archives preserve
the baseline, and repository status reports link exact evidence paths and hashes.
Keep copies of those archives separately when backing up; a Git push alone does
not upload ignored build artifacts. Public-release readiness is a separate gate.
