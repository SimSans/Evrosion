# Dependency inventory

The host frontend uses toml, serde/serde_json and sha2 for configuration,
manifests and artifact hashes. The UEFI image backend uses bootloader 0.11.17;
only the boot-contract adapter depends directly on bootloader_api 0.11.17.
These dependencies remain behind replaceable Internal implementation boundaries.

The [Cargo inventory](cargo-dependencies.json) records the authoritative current
set of distinct package/version pairs across Cargo.lock and the preserved [loader lockfile](bootloader-uefi.Cargo.lock),
including optional packages not compiled by the current feature selection.
It records exact versions, checksums, graph membership, upstream repositories,
license declarations, notice hashes and replacement scope. The published UEFI
loader is included even though it is the root package of its own lockfile.
License texts are preserved in [LICENSES/](../LICENSES/README.md).

The loader's build script runs a separately locked cargo install and rebuilds
core for UEFI. Root cargo fetch does not fetch that entire graph; the initial
image build needs network access. Preserve the upstream loader's Cargo.lock
unchanged when updating its version. Review both graphs and refresh the inventory
with `python3 tools/cargo_inventory.py` after fetching them. Some optional loader
packages need cargo fetch against the cached published loader manifest as well.
`python3 tools/cargo_inventory.py --check` works offline without a Cargo cache.

The bootloader subcrates omit license texts; their shared repository's license
files are taken from bootloader 0.11.17. usize_conversions declares MIT/Apache-2.0
but ships no texts: its original declaration and standard Apache-2.0 text are
retained, with that provenance explicitly recorded. The Noto bitmap crate's MIT
notice and the Noto glyphs' OFL notice are both retained. Inventory records do not
change upstream terms or constitute a production redistribution audit.

| Input | Resolution | Role and replacement |
|---|---|---|
| Rust toolchain | nightly-2026-07-10; components and targets in rust-toolchain.toml | Host/kernel/UEFI compiler; tested compatibility update in ADR-0001. |
| Python | Host Python 3.11 or newer, standard library only | Repository governance checks and their tests; no runtime OS dependency. |
| Git | Host-provided | Local source control. |
| actions/checkout | 3d3c42e5aac5ba805825da76410c181273ba90b1 (v7.0.1) | CI-only source checkout; replaceable workflow helper. |
| actions/upload-artifact | ea165f8d65b6e75b540449e92b4886f43607fa02 (v4.6.2) | CI-only build/evidence retention. |
| GitHub runner | ubuntu-24.04 | Host CI environment; not a hermetic release environment. |

Upstream terms: [Rust](https://github.com/rust-lang/rust/blob/af3d95584/LICENSE-MIT),
[Python](https://docs.python.org/3/license.html),
[Git](https://git-scm.com/about/free-and-open-source),
[checkout license](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/LICENSE),
[artifact action license](https://github.com/actions/upload-artifact/blob/ea165f8d65b6e75b540449e92b4886f43607fa02/LICENSE).
The checkout version is recorded in its
[upstream release](https://github.com/actions/checkout/releases/tag/v7.0.1).
Host tools are not bundled into an Evrosion image; Rust core/compiler-builtins
and the temporary UEFI loader are build inputs to the binary. Toolchain notices
and full release packaging remain part of production redistribution review.

Bootloader replacement is governed by
[EXC-0001](../architecture/exceptions/EXC-0001-temporary-bootloader.md).
Doctor reports QEMU/GDB versions and the selected firmware path and size;
boot evidence adds hashes of QEMU, firmware, image, kernel and embedded EFI bytes.
Their local host provision remains covered by EXC-0002; the CI workflow installs
host packages and does not claim a hermetic release environment.
