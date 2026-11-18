# Bounded immutable content and trust pointer

`ev-content-store` stores immutable, content-addressed byte objects in a fixed
append-only arena. One existing `ev-store` journal atomically publishes a
256-byte checkpoint containing append high-water and an optional object pointer.
It is safe `no_std` code with no allocator, custom journal, cryptographic
algorithm, filesystem, garbage collector or capability authority.

These are portable mechanisms. Actual Root storage routing, measured resource
admission, hardware durability and guest update execution remain integration
gates. A hash-verified object is not a signed or authorized release.

## Owned geometry and serialized access

The planned four-MiB test-disk profile is:

| Region | Physical sectors | Access through Backend |
| --- | --- | --- |
| Trust checkpoint | 128–141 | `Area::Checkpoint`, exactly14 local sectors |
| Immutable objects | 256–8191 | `Area::Objects`, exactly7936 local sectors |

The crate does not map physical sectors or acquire authority merely from these
constants. The actual adapter must own and validate those disjoint extents and
exclude every other writer. Existing System, AppRegistry, AppData, GrantPolicy
and Note extents are untouched. A real backend must enforce its absolute
monotonic deadlines and retain uncertainty; a successful flush means durable
completion, not a cache copy.

One `Arena<B>` owns one backend. `Backend::Device<'a>` exclusively reborrows it;
checkpoint Store and object-device scopes execute sequentially. One Root Block
window can therefore serve both regions without cloning the window or backend.
Stages, readers and verified tokens borrow the actual same arena exclusively.
Backend extraction transfers responsibility, not proof that accepted I/O is
settled. Stop/fence prior writers and resolve actual operations before any cold
replacement owner; never retry accepted unknown operations through another alias.

## Explicit provisioning and cold opening

`Provisioner::new` is an explicit owner-authorized new-volume operation with a
caller-supplied stable creation manifest. `scan` reads at most eight sectors per
step and requires the *whole* checkpoint and object regions to be zero. Foreign
or nonblank bytes refuse without writes. Only a completed scan permits
`finish` with a `MetadataCut`, which calls the existing Store formatter. It never erases or repairs.
No `open` failure selects provisioning automatically.

`Arena::open` uses `Store::open_mutable_namespace`. Before recovery may write,
that new bounded Store opening path requires the exact creation manifest in its
initial slot, untouched generation/lifecycle state, no KnownGood/second generation
and only a pending user-data mutation. Foreign pending Stage/Activate journals
refuse before replay. The consumer exposes only `WriteMutable`; ordinary Store
opening and generation semantics remain unchanged, with no added Store field.
The creation slot is immutable *in this consumer profile*, not a new claim about
all Store users. Valid pending checkpoint mutations use the existing recovery.
Corruption, unsupported formats and unformatted regions remain distinct errors.

Open returns checkpoint metadata, including `published_metadata`, rather than
implicitly trusting or reading an entire large object. Cold trust consumers
must stream and verify that referenced object before decoding accepted state.
Missing or damaged state must not fall back to `ReplayState::initial` or a remote
cached root. It requires explicit trusted recovery/provisioning.

## Reserve, stream, seal, verify, publish

A bounded object contains1–262144 payload bytes. Its public identity is the
SHA-256 of the exact payload; `Object::checked` reconstructs only a bounded
reference, not proof of stored bytes. Each reservation occupies one header sector
plus the payload's rounded-up sectors.

1. Capture one `TransferCut` before publication. `child(actualNow,budget)` returns
   a cut of at most1024 ticks, bounded by that exact original end. A stage/reader
   rejects a child from another transfer. Actual time and enforcement come from
   the adapter; these pure values do not qualify a clock. The entire256KiB object
   does not share a single8192-tick operation cut. `metadata(actualNow)` instead
   returns a distinct `MetadataCut`, bounded by the same original end and
   actualNow+8192, only for Store format/open/reserve/publish transactions.
   Chunk/header/read methods cannot accept that wider type. The actual backend
   independently captures every physical Block RPC at no more than1024 ticks,
   including inside those metadata transactions.
2. `begin(expectedHead,length,hash,transfer,metadata)` compares the exact checkpoint
   head under its `MetadataCut` and *durably journals the increased append
   high-water before any object write*. Only a complete Store receipt and exact mutable-payload readback
   returns a private `Stage`.
3. `Stage::write_chunk` writes at most4096 bytes sequentially. Every nonfinal
   chunk is sector aligned; final-sector padding is zero. It checks the original
   transfer cut and hashes exactly the accepted payload bytes. No retry,
   out-of-order write or overwrite API exists.
4. `Stage::seal` requires the exact length and expected hash, flushes payload,
   writes the canonical immutable header *last*, flushes again, and reads that
   exact header back. It returns a `Reader` rather than declaring success from
   writes alone.
5. `Reader::read_chunk` reads/hashes at most4096 bytes with newly captured child
   cuts under the original transfer. It checks final padding. Returned chunks
   are provisional until `finish` proves the entire exact expected hash. The
   caller must not authorize from partial bytes.
6. `Reader::finish` yields `Verified` retaining the sole actual arena borrow.
   After separately validating the complete trust/state bundle and current
   authorization, `Verified::publish(expectedHead,metadata)` atomically commits its
   pointer through Store and reads the exact checkpoint back. `release` returns
   only a reference, losing the verified publication token. A later publication
   must perform a complete new Reader verification.

`Verified` proves content integrity and actual backend association; it does not
establish publisher identity, metadata freshness, root continuity, executable
admission or owner activation consent. The trusted integration must bind signed
metadata, serialized replay state, artifact references and UTC floor together in
one immutable bundle and publish that one pointer only after every authorization
check. A separate System/KnownGood volume cannot participate in this transaction:
there is no cross-volume atomicity claim.

## Crash and uncertainty rules

Any potentially accepted I/O failure fences the arena before return. The same
owner refuses subsequent work without issuing more I/O. Cold Store recovery
resolves the original journal intent; no new operation/nonce/deadline is used to
retry accepted unknown work. Structural corruption and readback hash failure
also fail closed. Pure preflight failures publish no I/O.

An abandoned stage may leak its reservation. A header/data write, interruption
or failed publication never lowers high-water. Cold opening never reconstructs a
Stage or resumes writing its old extent. Later allocations append beyond it.
Objects are never overwritten, compacted or garbage-collected; finite capacity
ends with `NoSpace`. Old complete objects may remain unreferenced. This is a
bounded availability cost, not permission to reset trusted floors or format.

The current pointer wire is `EVCTRS01`, version1: high-water at16, revision at24,
optional object flag at32 and the56-byte object reference at40; other bytes are
zero through256. The object header is `EVCOBJ01`, version1: reference at16,
reserved zeros and SHA-256 of bytes0–479 at480. References encode local start,
sector count, length and payload digest. These hashes detect corruption, not
hostile physical modification or rollback of the entire medium.

`ev-release-trust::checkpoint` separately serializes all retained `ReplayState`
fields into canonical1024 bytes. It checks exact trusted root/binding association,
preserves every target/version/UTC floor including withdrawn targets, and has no
initialization fallback. Store it with the exact root/metadata in the same
hash-bound bundle. Local KnownGood rollback must not lower remote trust floors;
this crate does not select a System generation or activate software.

## Verification scope

Tests use the real Store implementation over one8192-sector device model, with
separate cache/durable bytes. The actual I/O boundary matrix interrupts each
read/write/flush before, after and with torn persistence, then cold reopens and
checks old-or-complete pointers, full referenced bytes, reservation bounds,
poisoned refusal and unchanged bytes outside both regions. Additional tests
cover foreign/unformatted/late-nonblank volumes, abandoned reservations/capacity,
immutable cuts, bad chunks, wrong hashes, malformed headers and padding. Store
adds targeted foreign-pending refusal and interrupted mutable-only recovery
tests; ordinary Store regression tests remain required.

These tests prove bounded software ordering under the stated SectorIo model.
They do not certify PIO hardware, a Root shared-window adapter, malicious-medium
rollback resistance, current signed-update acceptance or a complete M6 milestone.

## Root network adapter

The additive `ev-store::network` route maps Root logical80–93 to checkpoint
physical128–141 and logical128–8063 to object physical256–8191. Every guard stays
closed. Old native/session/File mappings reject these logical sectors. The
measured Block actor must explicitly select its `native-network` feature and
`Routes::new_network`; packets cannot select the profile or receiver identity.
Physical PIO success is translated back to the original *logical* sector in the
acknowledgement. A physical-sector reply is not a Root logical acknowledgement.

Root's `native_plan::storage::content::BackendRef` GAT adapter reborrows the one
existing Backend/window and uses its actual session preflight, fixed child cut,
canonical reply check and uncertain-I/O fence. `State::content_backend` refuses
recovery or pending registry/grant/System intent before lending it. This does not
create an actual update operation, consume owner consent or acquire any new cap.
The trusted integration must preserve content-owner failure state and settle
actual transport debt; dropping a borrow is not a hardware recovery mechanism.

`creation_manifest(ownerNamespace,volume)` binds independently provisioned,
retained nonzero identities to the stable `FORMAT_ABI`. It contains no current
Root executable/startup hash, online key or mutable cache input. Its Store
supervisor/health fields explicitly name *creation metadata*, not an executable
or actual health. The mutable-only namespace does not call BeginBoot, Admission,
Health or SelectKnownGood; formatter selection is not proof of a healthy boot.
Keep the same actual creator context across Root updates and cold recovery.

Root/Block route and adapter tests operate through the real bounded wire codecs,
Block route selection, shared-window operations and Store journal. Actual Kernel
source identity, physical device authority, measured actor images, guest disk
mutation and signed-update acceptance remain separate integration proof.
