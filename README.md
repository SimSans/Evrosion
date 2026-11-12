# Evrosion

Evrosion is an operating system being built to make computers easier to use,
configure and recover while preserving their full power and the owner's control.
Its foundation is a capability kernel, isolated userspace services, native
applications and recoverable System Generations. Local operation, accessibility
and deliberate owner control are part of the product direction.

**Early development — 0.1 Developer Preview source snapshot.** The current target
is x86-64 UEFI under QEMU Q35/TCG. This is a bounded architecture demonstration,
not an interactive daily desktop or an installer for personal hardware.

The 0.1 engineering checkpoint demonstrates:

- Native `.zion` package installation, activation, update and rollback, with
  private data retained through removal and reinstallation.
- Selected-file READ access, explicit remembered permissions and revocation.
- App and Shell fault containment, replacement, structured crash records and
  resource inspection.
- A provider change behind an unchanged consumer endpoint.
- Health-gated System selection, failed-candidate rollback and an independent
  basic recovery path with usable data preserved.

See [scope and limits](docs/release/0.1-preview.md) and
[source identity](SOURCE_IDENTITY.md). Historical engineering acceptance and this
publication snapshot have separate source identities. Exact build and validation
records identify which bytes were tested. This repository is not a signed
official image release.

## Build and run

Use the [Linux quickstart](docs/development/QUICKSTART.md). After provisioning the
pinned compiler and host tools:

```bash
cargo fetch --locked
cargo ev doctor
cargo ev build
cargo ev run
```

`run` opens a bounded graphical demonstration. Its input is scripted; it does not
leave a manual desktop session running. It uses an owned test disk. Keep the
image away from irreplaceable data and physical system disks.

`run` selects a Native fixture. Build a normal image again before generic boot
checks or GDB:

```bash
cargo ev build
cargo ev test boot --runs 3 --timeout 60
cargo ev debug kernel --batch
```

## Development

- [Technical architecture](architecture/README.md),
  [invariants](architecture/INVARIANTS.md) and [ADRs](architecture/adr/README.md).
- [Engineering governance](architecture/GOVERNANCE.md).
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md) and
  [license status](LICENSES/README.md).
- [Dependency inventory](third_party/README.md) and [performance methods](PERFORMANCE.md).

Networking, sustained interactive sessions and one physical reference target are
next-stage work. Broad hardware support, production authentication, a consumer
installer and compatibility runtimes are not implemented by this preview.

Generated images, raw VM runs and compiler outputs stay under ignored `build/`
and `target/`. Share diagnostics only after checking them for private data.
