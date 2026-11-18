# Evrosion

Evrosion is an operating system being built to make computers easier to use and configure while preserving their power and the owner's control. Recovery, accessibility, local operation and deliberate control are part of that goal. A small capability kernel, isolated services and recoverable System Generations provide the foundation.

**Current source checkpoint: unfinished 0.4 development.** This update includes the work since the published 0.1 preview, including the 0.2 connected developer alpha, the 0.3 document workflow and the current native workspace implementation. All fourteen full 0.4 acceptance gates remain open. This is an unsigned development source checkpoint.

The native workspace includes Files, Editor and Inspector, larger documents, multiple windows, scoped file access, ordinary namespace operations, protected controls, semantic interfaces and local application installation. Individual components have bounded engineering results. Those results do not establish acceptance of this public edition or a complete integrated desktop. See [current status](docs/status/PROJECT_STATUS.md), [0.4 progress](docs/status/M8_PROGRESS.md) and [source identity](SOURCE_IDENTITY.md).

## Build and explore

The current reference target is x86-64 UEFI/QEMU on a prepared x86-64 Linux host. Start with the [Linux quickstart](docs/development/QUICKSTART.md) for the pinned toolchain and prerequisites. Initial dependency provisioning needs network access; subsequent checks can use the cached graphs.

```bash
cargo ev doctor
cargo ev --help
```

The earlier bounded graphical demonstration remains available through `cargo ev run`. It uses a disposable runner-owned disk and requires a graphical Linux session with QEMU GTK. The [0.3 document-session guide](docs/development/DOCUMENT_SESSION.md) describes its separate retained-data workflow.

The unfinished 0.4 workspace has an explicit, feature-gated qualification frontend:

```bash
cargo run -p ev --features workspace -- workspace --help
```

See [workspace development](docs/development/WORKSPACE_04.md). Keep existing data and its retained executable cohort together; never resolve a compatibility refusal by reformatting or replacing the original volume.

## Develop

- [Architecture overview](docs/development/ARCHITECTURE.md), [architecture index](architecture/ARCHITECTURE_INDEX.md), [invariants](architecture/INVARIANTS.md) and [ADRs](architecture/adr/README.md).
- [Native package guide](docs/development/ZION.md), [debugging](docs/development/DEBUGGING.md) and [performance methods](PERFORMANCE.md).
- [Experimental source deltas](development/experimental/README.md) preserve pending reclamation, observation and recovery work separately from the default implementation.
- [Contribution guidance](CONTRIBUTING.md), [security reporting](SECURITY.md), [license policy](LICENSE_POLICY.md) and [legal status](LEGAL.md).

Core software uses GPL-3.0-only; the seven fixed interface roots use Apache-2.0; eligible prose uses CC-BY-4.0. Third-party terms remain intact. The file-level assignments in [REUSE.toml](REUSE.toml) govern their respective materials.

## Limits

Physical hardware qualification, consumer installation, broad device support and a signed official release remain separate work. Automated VM observations and screenshots are distinct from human usability acceptance. Historical proofs identify their own source bytes; publication edits and later source changes need their own verification.

Generated images, caches, private session data and raw execution archives are excluded from this repository. Preserve test failures and their inputs alongside later successes. The existing `v0.1.0` tag remains unchanged; this checkpoint creates no 0.4 release tag.
