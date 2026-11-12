# Linux quickstart

Use a writable x86-64 GNU/Linux checkout. Ubuntu 24.04 with QEMU 8.2, OVMF and
GDB is the reference development environment. KVM is optional; the Evrosion
conformance workflows use TCG. A graphical Linux session and QEMU GTK are needed
for the visible demonstration. Hosted CI configuration is not evidence that a
hosted run occurred.

## Prepare the host

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install --yes --no-install-recommends build-essential git python3 qemu-system-x86 qemu-system-gui ovmf gdb
```

Python 3.11 or newer and Rustup are required. Install Rustup using a trusted host
setup, then install the repository's exact compiler pin:

```bash
rustup toolchain install nightly-2026-07-10 --profile minimal --component rust-src,rustfmt,clippy,llvm-tools-preview --target x86_64-unknown-none,x86_64-unknown-uefi
```

`rust-toolchain.toml` is authoritative. Do not substitute an arbitrary newer
nightly or inject `RUSTFLAGS`, compiler wrappers or a custom `RUSTC` into recorded
builds. The builder supplies its target flags and records source/artifact hashes.

From the repository root:

```bash
cargo fetch --locked
cargo ev doctor
cargo ev build
```

The first build may use the network. The temporary UEFI loader has a separately
locked Cargo graph, so workspace `cargo fetch` alone does not prepare every
loader dependency. Keep both lockfiles and the [inventory](../../third_party/README.md).

Doctor checks prerequisites without installing software or starting a VM. It
returns 0 when required checks pass, 1 on failed checks and 2 for invalid input.
A changed tracked lockfile is a real review condition; do not reset or regenerate
it merely to silence the check. Host tests need checkout-local scratch writes.

OVMF is discovered from supported distro paths. An explicit override must name
an actual readable firmware file; invalid overrides fail instead of falling back:

```bash
cargo ev doctor --ovmf-code /path/to/OVMF_CODE.fd
```

## Run the graphical demonstration

```bash
cargo ev run
```

This builds the Native demonstration and opens a real QEMU GTK window. Recorded
keyboard and owner-command stimuli exercise the launcher, selected-file access,
faults and restoration. The demonstration ends after its bounded workflow.
It does not provide an unrestricted manual desktop session or write to a physical
disk. Headless graphical conformance is available separately:

```bash
cargo ev test desktop-graph
cargo ev test native-platform
cargo ev test native-owner-grants
cargo ev test native-system
cargo ev test provider-switch
```

These dedicated workflows rebuild their own fixtures and retain their actual
logs, captures and private disks. A command existing or compiling is not proof
that its runtime acceptance passed in your checkout.

## Normal boot and debugging

The visible command changes the selected build. Reselect normal before generic
boot checks and debugging:

```bash
cargo ev build
cargo ev test boot --runs 3 --timeout 60
cargo ev debug kernel --batch
```

The host command succeeds only when the expected guest protocol, build identity
and QEMU exit agree. A normal test guest exits through debug status 33; the host
command returns 0. Timeouts, malformed/truncated output and unexpected faults fail.

After successful dependency preparation, set `CARGO_NET_OFFLINE=true` and
`RUSTUP_AUTO_INSTALL=0` for cached offline runs. This is not an offline build from
an empty host.

## Checks and retained output

```bash
cargo fmt --all -- --check
cargo test --locked --offline -p ev -p ev-kernel -p ev-zion -p ev-app-registry -p ev-picker -p ev-grant-policy
cargo clippy --all-targets --locked --offline -- -D warnings
python3 tools/check_architecture.py
python3 tools/cargo_inventory.py --check
```

Workspace defaults do not cover every feature-specific or bare-metal test.
Run the workflows and target checks relevant to a change. A clean committed
candidate can also exercise two-clone local reproduction:

```bash
cargo ev image --verify-reproducible
```

The command rejects a dirty source tree. Two-path local equality is distinct
from an independent rebuild or a hermetic cross-host result.

Exact artifacts and symbols live under `build/m0/artifacts/`; each run retains
its selected manifest, serial output, stderr and command. Other workflows use
`build/m3/`, `build/m4/` and `build/m5/evidence/`. The printed Evidence path
identifies the actual run; the latest global manifest is not a historical record.
Do not erase a failed run to replace it with a later success.
