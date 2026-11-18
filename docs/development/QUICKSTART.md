# Linux development quickstart

The build/run guide passes on a fresh Ubuntu 24.04/Linux 6.8 KVM guest (local engineering archive)
for tested source `b73186a8c6738e62ce0f7fc7e062615dd39926fcc2a58d84d29c54365fe6501b`.
Verified pinned Rustup/toolchain and compressed crate caches were reused; no
Evrosion compiled objects were imported. The original extra read-only source
mount passed the actual GUI/boot/GDB/reproduction routes, then blocked eight
storage host tests' checkout-local scratch writes. That failure is retained;
the unchanged tests/architecture/inventory passed in a new clean writable copy
of the exact same source. This is combined same-source validation, not one
uninterrupted directory or a fresh-network toolchain-install claim. Current
status/evidence notes are subsequent derived documentation.

## Prerequisites

Use x86-64 GNU/Linux. Doctor currently requires Rustup, the exact repository Rust
pin on PATH, Python3.11+, Git, QEMU with Q35/TCG/`isa-serial`/`isa-debug-exit`, a
readable nonempty OVMF CODE image, GDB and writable/searchable build directories.
The host compiler/linker and ordinary build tools are also needed. KVM is optional;
the proof workflows use TCG. The configured CI recipe targets Ubuntu 24.04; that
configuration is not evidence of a completed hosted CI or fresh-machine run.

For a Debian/Ubuntu host, the provisioning recipe is:

```bash
sudo apt-get update
sudo apt-get install --yes --no-install-recommends build-essential git python3 qemu-system-x86 qemu-system-gui ovmf gdb
```

Install Rustup through your chosen trusted host setup, then enter the repository
root. The exact current compiler setup is:

```bash
rustup toolchain install nightly-2026-07-10 --profile minimal --component rust-src,rustfmt,clippy,llvm-tools-preview --target x86_64-unknown-none,x86_64-unknown-uefi
```

`rust-toolchain.toml` is authoritative if the pin changes through review. Do not
replace it with an arbitrary current nightly. QEMU/OVMF/GDB are host-provided;
doctor checks their required features and records versions rather than declaring
all distro versions interchangeable or pinned.

## Initial dependency preparation

```bash
cargo fetch --locked
cargo ev doctor
cargo ev build
```

The first image build may use the network. The temporary EFI loader has a
**separately locked Cargo graph**; fetching the workspace alone does not fully
cache it. The initial image build prepares that graph and the image-builder cache.
This is provisioning, not an offline-from-empty-machine claim. See the
[dependency inventory](../../third_party/README.md).

Doctor returns0 when required checks pass,1 for failed checks,2 for invalid
arguments. It does not install tools or start a VM. The first `cargo ev` invocation
may compile the host frontend. A changed tracked Cargo.lock deliberately fails
doctor's lock-revision check; review the change, do not overwrite/regenerate the
lockfile simply to silence it. A dirty engineering snapshot cannot be reported
as a literal clean-checkout quickstart PASS by ignoring that result.

Firmware is selected by explicit CLI path, then `EV_OVMF_CODE`, then known distro
locations. An invalid explicit path fails rather than falling back. Generic boot
commands accept separate CODE/VARS overrides:

```bash
cargo ev doctor --ovmf-code /path/to/OVMF_CODE.fd
cargo ev run --ovmf-code /path/to/OVMF_CODE.fd --ovmf-vars /path/to/OVMF_VARS.fd
```

Those paths are examples to replace with actual files. The usual adjacent
CODE→VARS name is discovered automatically. Dedicated platform workflows accept
no firmware flags; use the actual supported environment/discovery path or extend
the frontend through a reviewed change.

## Cached offline boot and tests

After successful preparation, these commands request offline Cargo resolution
and disable implicit toolchain installation:

```bash
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev doctor
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev build
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev run
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev build
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev test boot --runs 3 --timeout 60
cargo test --locked --offline -p ev -p ev-kernel -p ev-zion -p ev-app-registry -p ev-picker -p ev-grant-policy
python3 tools/check_architecture.py
python3 tools/cargo_inventory.py --check
```

The normal boot prints a matching build ID and ordered kernel result, and the
host succeeds only after the expected guest result and QEMU exit status agree.
Host success is0; the expected guest debug-exit status is33. A timeout, panic,
malformed/truncated record or wrong build fails. `run` builds a bounded visible
Native demonstration using QEMU GTK and a new private disk. Its recorded owner
commands and keyboard events are explicit test stimuli; it does not leave an
unbounded interactive desktop session. A graphical Linux session is required;
headless conformance uses the dedicated commands below. Physical validation of
this front door now passes on the prepared host (local engineering archive).
The final supported-environment result is linked above; its actual GTK run also
passes with recorded untrusted SSH-X forwarding to the graphical session.

Do not inject `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, compiler wrappers or a custom
RUSTC into recorded builds. The builder rejects them and supplies the measured
target flags itself. Keep sources unchanged during a build; the builder rejects
a changed source snapshot. Rebuild after source edits. Host tests require a writable
checkout for their scratch fixtures; run them separately from builds against the
same copy.

## Graphical and native development proofs

```bash
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev test desktop-graph
```

This builds and runs a genuine graphical guest with isolated services, actual
keyboard/UART stimulus and unmodified QMP captures. It is a headless automated
acceptance workflow; view the retained captures and results in its printed
`build/m4/evidence/` directory. It does not leave a desktop
window open. The command owns a fresh private test disk and accepts no arbitrary
physical disk path.

```bash
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev test native-platform
```

The Native workflow owns six cold boots over one continuing private disk and
retained A/B packages. It imports the exact4MiB accepted M4 checkpoint from the
committed immutable proof through a bounded decoder, into a new owned disk. A
historical local raw origin is crosschecked if present; it is neither required
nor rewritten. No blank substitute or host formatting is used. The
current-code six-cold lifecycle regression (local engineering archive)
passes.

Native3 adds two separate continuing-disk workflows, with retained passing
actual owner-permission (local engineering archive)
and System-recovery (local engineering archive)
proofs:

```bash
cargo ev test native-owner-grants
cargo ev test native-system
```

The first verifies explicit owner consent, durable READ policy, cold fresh remint,
revocation and post-reboot refusal. The second combines actual graphical fault
recovery with a faulty selected System generation, real health failure, protected
Good return and an independent basic recovery path. Source markers alone do not
accept either proof.

`cargo ev test provider-switch` is the separate source-built provider replacement
workflow. Its current physical status belongs in M5 progress. A listed command,
successful compilation or parser/model test is not an executed platform PASS.
Dedicated workflows rebuild their required fixture; generic `test boot` rejects
those fixture images rather than guessing their devices or disks.

## Experimental V4 network reference profile

```bash
cargo ev network
cargo ev test network-probe
```

Both commands explicitly build the optimized **release** V4 reference Kernel.
Earlier full V4 development builds exceeded the unchanged 256 KiB linked-stack
bound and were refused before any VM. Those failures remain retained with their
original sources. These commands select the release reference profile; a passing
release build does not qualify a different profile. Every run checks its actual selected ELF and stack census.
This is an explicit build policy, with no stack, CPU quota or operation-deadline
increase and no fallback to another image after a failed check.

`network` attempts a manual graphical session. `test network-probe` is a separate
headless 240-second probe: actual native DHCP/DNS, a fixed plaintext `/hello`
exchange, elapsed-source observations and checked owner-requested shutdown. It
requires the exact reviewed QEMU source profile and a C compiler for its verified
prelaunch clock module; this is narrower than the ordinary M0 host prerequisites
above. The recorded automated `finish` input is not human consent. Networking,
RTC elapsed time and compilation do not establish UTC, TLS, publisher/update
trust, physical-device support or complete 0.2 acceptance. Consult the retained
run result for actual execution status; listing these commands makes no PASS claim.
The complete qualified 0.2 scope is now recorded in M6 readiness.
Use the [local walkthrough](M6_WALKTHROUGH.md) for sustained interaction and
saved-data reopening in the selected qualified checkout.

## Where results go

`build/m0/manifest.json` identifies the latest successful build. Complete artifacts
and unstripped symbols live beneath `build/m0/artifacts/`; runs retain their exact
manifest, serial/stderr and commands. Dedicated proofs use `build/m3/`, `build/m4/`
and `build/m5/evidence/`. Earlier successful or failed evidence is preserved.

Running different workflows changes the latest manifest. Before generic `test boot`
or GDB kernel boot, use a new normal `cargo ev build`. `run` selects its own
explicit Native demonstration build. See
[debugging](DEBUGGING.md), [architecture overview](ARCHITECTURE.md) and the
[`.zion` guide](ZION.md).
