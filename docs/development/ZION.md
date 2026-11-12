# Minimal `.zion` development guide

`.zion` is Evrosion's native immutable application container. Its current format,
ABI, tools and role layout are **Internal**; there is no Stable third-party SDK or
general `ev install` command. Historical imported plans call it `.sion`.

Actual implementation is in [ev-zion](../../libs/zion/src/lib.rs), its
[host producer](../../libs/zion/src/producer.rs), the
[Hello producer](../../tools/ev/src/native_package.rs) and
[Native graph builder](../../tools/ev/src/supervisor/native_graph.rs).
[ADR-0048](../../architecture/adr/ADR-0048-internal-zion-package-and-activation-metadata.md)
defines the bounded model; [ADR-0049](../../architecture/adr/ADR-0049-native-root-package-banks-and-durable-app-state.md)
defines actual package banks and durable app state.

A package contains a canonical manifest, one ELF64 executable, optional contained
resources, contract requirements, capability requests and content hashes. The
manifest separates stable AppId, human name/source, optional publisher claim,
version, build ID, platform/ABI and readable data-schema range. Package content
digest and publisher claim are distinct from stable AppId and authority.

The library bounds packages to2MiB, manifests to4KiB, entries to16 and declared
contracts/capability requests to8 each. The current Native runtime's measured
readonly banks impose the smaller63-page container bound. Unknown required
format/ABI/contract semantics, wrong hashes, ambiguous paths and incompatible
schemas fail rather than widening access or erasing data. Exact ELF W^X, entry,
stack, role/quota and source admission remain separate from container parsing.

The host producer API is:

```rust
ev_zion::producer::build(&spec, executable_bytes, resources)
```

`Spec` supplies the fields above; resources have canonical contained paths and
bytes. This creates data, not installation permission or a running process.
For the real Hello path, `ev::native_package::native_hello` additionally binds the
actual executable plus canonical App metadata/resources and checks the graph's
executable admission. Unrelated OS/document source changes do not change this
App content identity; complete source provenance remains in the outer build and
catalogue.
It is a library API used by the builder, not an existing standalone packaging CLI.

To build the current measured reference packages without starting a VM:

```bash
CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 cargo ev build --fixture m5-native
```

Use the resulting `build/m0/manifest.json` supervisor-artifact list to locate
`m5-native-Hello-A.zion`, `m5-native-Hello-B.zion`, the actual ELFs and catalogue.
Each build uses a unique artifact directory; do not hard-code a hash-specific
path. The A/B versions share AppId/schema and contain distinct actual executable
and package identities. This fixture changes the latest manifest; generic
`cargo ev test boot` intentionally refuses it. Use the dedicated Native workflow,
which imports its exact accepted reference checkpoint from the committed proof.

Actual Hello uses internal File/focused-input/surface contracts; the Native
variant also requests app-private data. A selected File declaration grants
nothing on its own. Root checks the actual package and current process, and a
real owner selection produces one scoped READ endpoint. Runtime handles, PIDs,
endpoint numbers and monotonic consent deadlines are never serialized as durable
permission. Installation/activation and private app data are separate records.

The actual Native suite tests owner-command install/activate/stage/update/rollback/
remove/reinstall on its owned test disk. It is not a general external installer,
marketplace, publisher authentication service or migration utility. Removal
retains app-private data in the bounded profile.

Useful component checks are:

```bash
cargo test --locked --offline -p ev-zion -p ev-app-registry -p ev-picker -p ev-grant-policy
```

Changing the whole source build input currently changes Native app build/package
identity even if the app ELF is unchanged. Cross-build deployment needs explicit
retention of referenced packages and compatible stable data namespace handling;
do not reset a namespace to conceal missing package references.
