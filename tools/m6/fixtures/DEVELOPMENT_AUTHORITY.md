# Development download fixture authority

`development-root.bin` is the independently provisioned public development
anchor. Its SHA256 is
`3d41b2402fcde61e047585759d3bfa489033100d7bd2fe2661d7653c15ef5ed8`.
The adjacent JSON records the five public keys, binding, author validity labels
and disjoint role policies: Root2-of2, Targets1, Snapshot1, Timestamp1.
This authority is **DEVELOPMENT**, not Official Evrosion.

The initial author window is2026-11-12T00:00:00Z through2027-11-12T00:00:00Z.
Those labels and future Host metadata author dates are inputs, not evidence of
acceptable current UTC. Consumers still need independently qualified time,
atomic durable replay/floor state, exact artifact checks and executable
admission. A downloaded Root/key list cannot replace this source anchor.

Five fresh OS-CSPRNG private keys were provisioned only in the ignored owner's
`build/m6/development-signing` directory, mode0700 with mode0600 key files.
Source, logs, receipts and serving objects contain public data only. Missing,
corrupt, wrong, exposed or partial private material refuses; load never
regenerates keys. Source clones do not possess these signing keys. The public
Host API's explicit initial provision operation refuses an existing anchor,
including when its private files are absent.

`ev::download_fixture::produce` separately compiles cold reference A/B and
downloaded B/C artifacts under a frozen source pin. It retains raw/debug-separated
ELFs, exact LOAD/stack/role/frame checks and self-contained Zion packages. It
emits no Kernel bank/include/catalogue entries. B keeps the same AppId and scalar
and Note schemas; C executes a genuine pre-Ready invalid-opcode fault.
`sign_fixture` checks those actual component/package bytes before signing the
bounded metadata chain. `sign_with_authority` lets a frozen build copy borrow an
explicit Host signer while requiring the same independent public anchor; no
private key copy is needed. The returned Fixture serves only six immutable exact
paths and retains no signer. HTTP transport grants neither trust nor authority.

## Sequential same-app phases

The original six-route fixture is a two-artifact comparison set. M6 update
experiments instead use `FixturePhase::B` and `FixturePhase::C` with `sign_phase`:
one target and one `/artifacts/hello.zion` payload per phase. The independently
expected logical target name is SHA256 of the domain
`evrosion.DEVELOPMENT.logical-app-target.v1\0`, the stable HelloAppId, then the
authority binding's namespace, channel and platform bytes. Filenames, candidate
digests, key rotations and App claims do not choose a new replay-floor name.
The independently retained ROM fixture is `development-target.rs`; its value is
`bd1abada3a118c4775e0d9ccd04677b68ede2e72955194e82d7796c9f9348f76`.
The Host derivation checks that literal. The actual Source Root selection must
pin this same name and the App/package/contract relationship before committing
the common verifier's proposed state; AppId equality alone is insufficient.

B has artifact version2 and initial Targets/Snapshot/Timestamp version1. C has
artifact version3 and initial metadata version2 under the same Root1. Each
candidate has distinct generation/release identities bound to its selected
package, source, build and descriptor. An explicit later validity refresh must
use the real signer and a monotonic metadata version; it cannot lower the
artifact version or reset retained state. Author labels still provide no UTC
qualification.

Common-verifier tests retain B's proposed ReplayState in test memory, verify C,
then refuse both the original remote B metadata and freshly re-signed B under
newer metadata. The independently expected selection boundary also refuses the
same AppId under a newly named unrelated target. These tests use a clearly
synthetic TEST time window and prove no durable commit or actual clock source.
Already installed local KnownGood B requires separate OS recovery authorization;
the Host fixture exposes no KnownGood grant or rollback-floor reset.
