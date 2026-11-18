# ev

`ev` is the Rust host frontend for building, running and testing Evrosion. Cargo
is its replaceable Internal backend. The Cargo alias selects a separate
`host-tools` profile with optimized SHA-256 for fresh source/artifact hashing;
nested Kernel and userspace builds retain their declared profiles. Its CLI is
not a Stable public SDK. See the
[Linux quickstart](../../docs/development/QUICKSTART.md),
[debugging guide](../../docs/development/DEBUGGING.md) and
[current status](../../docs/status/PROJECT_STATUS.md).

```bash
cargo ev --help
cargo ev doctor
cargo ev build
cargo ev test boot --runs 3 --timeout 60
cargo ev debug kernel --batch
cargo ev run
cargo ev test desktop-graph
cargo ev test native-platform
cargo ev test provider-switch
cargo ev test native-owner-grants
cargo ev test native-system
cargo ev test ipc-bench
```

`doctor` checks without installing or starting a VM. `build` creates an unsigned
UEFI image, symbols and source/artifact manifest. `test boot` verifies the current
normal kernel image. `run` builds and displays one scripted Native demonstration
on a new private disk, with real scanout checks and ordinary cleanup. It needs a
graphical Linux session, QEMU GTK and exactly one CPU; default timeout240 seconds.
The actual visible route (local engineering archive)
passes; final whole0.1 readiness remains separate.
The dedicated graphical/native/provider workflows build and validate their own
closed fixtures. Listing a workflow does not establish its current physical PASS.
`ipc-bench` is a separate five-VM checked SDK RPC batch; its first actual
baseline (local engineering archive)
passes. Delivered guest IRQ ticks alone are not calibrated elapsed latency, and
a zero span means below resolution. Host bounds include the complete batch's
barriers, scheduling, framing and delivery.

Other actual dedicated workflows are:

```bash
cargo ev test storage-pio
cargo ev test storage-journal
cargo ev test storage-generation
cargo ev test storage-file
cargo ev test storage-progress
cargo ev test storage-recovery
cargo ev test display-surface
cargo ev test m0
cargo ev test architecture --milestone M0
cargo ev image --verify-reproducible
cargo ev bootstrap
cargo ev mission --open
```

Storage/recovery tests own fresh private persistent test disks; none accepts an
arbitrary physical disk path. `cargo ev recover --from PREPARED_OWNER_SUITE`
resumes a specific retained owner-recovery suite through actual current-prompt
stdin. An arbitrary directory or raw image is not a recovery capability.

The Native runners import the exact accepted M4 checkpoint directly from the
committed immutable proof into a new owned disk. Historical raw files are optional
and strictly crosschecked if present. No historical origin is rewritten and no
blank substitute is formatted.

Generic build accepts `--root PATH` and `--profile dev|release`. Run/boot/debug
accept their declared firmware/deadline/CPU options. The Native preview requires
one CPU; M0 boot/debug accepts1..64.
Firmware override order is CLI, `EV_OVMF_CODE`, known distro paths; an invalid
explicit override fails. VARS normally derives from adjacent CODE naming.
Dedicated workflows take no extra options; consult actual `--help` before adding
flags. Native userspace proofs remain bounded BSP/controlled devices regardless
of firmware CPU enumeration.

Builds record the exact toolchain, source revision/dirty state, tracked and
untracked source hashes, both lockfiles, inputs and artifacts. They reject source
changes during build and injected compiler flags/wrappers. Each build has a new
artifact directory; only success publishes the latest manifest. No initial Git
commit or official signature is manufactured. A cached offline run uses
`CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0`; both Cargo graphs and the pinned
toolchain must already be provisioned.

Run verifies artifacts, uses Q35/TCG, owns firmware variables and isolated disk
writes, disables networking/monitor, bounds output/time and kills/reaps its child
on failure. Matching build/ordered complete serial protocol/expected guest exit
must all agree. Host success is0; bad arguments2; ordinary failures1. Guest debug
exit33 is translated to success only after validation.

Evidence is retained below `build/m0/`, `build/m3/`, `build/m4/` and `build/m5/`.
Those directories are ignored, while selected immutable portable proof records
are tracked. Keep raw evidence with its exact manifest and snapshots. A later
source build is not automatically acceptance of the earlier cumulative milestones.

The [dependency inventory](../../third_party/README.md) covers both locked graphs.
[M0 acceptance](../m0/README.md) retains the original panic/GDB/rebuild workflow
details. The public [implementation status](../../docs/status/PROJECT_STATUS.md)
identifies the current native scope.
