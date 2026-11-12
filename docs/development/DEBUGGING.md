# Debugging and evidence

Start with the exact result directory printed by the failing command. Keep its
`results.json`/`phase-results.json`, raw `serial.log`, stderr, QEMU command,
manifest, images/packages and disk snapshots together. A summary line without
its matching build/artifacts is insufficient. Preserve the failed attempt before
changing code; reruns create new evidence directories.

The normal kernel path supports source-level GDB:

```bash
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev build
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev debug kernel --batch
```

Batch mode checks the actual entry breakpoint, source line and backtrace and
retains `session.gdb` plus `gdb-transcript.txt`. For an interactive session:

```bash
cargo ev debug kernel
```

QEMU begins paused, with its GDB listener bound to loopback. `continue` reaches
`evrosion_kernel_entry`; use `bt`, then `detach` and `quit` to resume/finish the
owned run. Symbols come from the verified unstripped ELF. The generated script
maps `/evrosion` source paths back to this checkout.

A deliberate panic is a negative fixture:

```bash
cargo ev build --fixture panic
cargo ev test panic
cargo ev debug kernel --batch
cargo ev build
```

`test panic` expects the declared panic result/build/source location and guest
failure exit35. Generic `test boot` must reject a failing fixture. The last normal
build restores the ordinary latest manifest. Do not call a deliberate failure a
successful platform boot.

The GDB route above is the existing normal/panic kernel fixture route. Native,
desktop and provider tests use their dedicated owned runners; the generic command
does not attach to an arbitrary live acceptance VM or accept its private disk.
Changes to that integration require an explicit implementation, not an invented
debug flag.

Graphical evidence contains unmodified PPM scanout captures and QMP/input
transcripts. Compare actual pixels and current process identities, not just a
host reference or a Ready marker. Native diagnostics collect crash registers
before reap and correlate them with actual fault/query observations; their
physical status and retained artifacts are recorded by the current M5 proof.
An empty/partial diagnostic or unavailable System admission remains unavailable,
not an inferred KnownGood generation.

Disk inspection is read-only. Never repair, format or overwrite an acceptance
snapshot to make a check pass. Guest persistence/recovery decisions and host
observer validation are separate. A kernel panic, App fault, failed health gate,
normal Stop and host timeout are different outcomes and should stay labeled.
