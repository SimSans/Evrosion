# ev-workspace-store

Safe `no_std` userspace dataset over an exclusively owned `ev_store::SectorIo`
region. The bounded reference has256 dynamic entries,32 directories, depth8,
1MiB files,64MiB committed allocation and2MiB isolated staging reserve.

Read the [format and adapter contract](../../architecture/designs/WORKSPACE_STORAGE.md)
and [ADR-0104](../../architecture/adr/ADR-0104-bounded-workspace-dataset-and-durable-namespace.md).
It does not interpret/migrate existing File-v1/Store-v2 data, grant capabilities
or establish device/window quiescence. Focused tests are portable host byte and
I/O-failure evidence; target service/VM qualification remains pending.

Provisioning and full hash verification have bounded caller-driven
continuations. Metadata open reads130 sectors; it never silently scrubs64MiB
at startup. Every returned data chunk is verified. Original uncertain operation
retry reconciles its exact authenticated client scope and persistent receipt;
fresh operations cannot pass an incomplete root mirror.

Initial qualification used a temporary standalone Cargo workspace. The package
is now an explicit member of the selected W workspace; focused checks use
`cargo test --offline --locked -p ev-workspace-store`. The initial manifest/lock
preimages and integration audit are retained in the M8 run directory.
`QUALIFICATION.json` pins that initial qualification snapshot; subsequent atomic
restore qualification is recorded separately. Scratch must be caller-owned
resident storage; no catalog or document belongs on a service stack.
