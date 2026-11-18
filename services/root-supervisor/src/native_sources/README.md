# Scoped native package sources

`native_plan::Packages` continues to verify and resolve only the measured,
immutable compiled A/B banks. Its `Slot` enum and bank-returning State APIs do
not recognize downloaded content.

`native_sources::Source` distinguishes a compiled bank from downloaded B/C.
`Downloaded::from_images` borrows an actual sealed `Images<T>` owner and the
current acquisition `Snapshot`, checks exact retained Content membership, and
parses the actual readonly package. It checks full package/object identity,
AppId, build, source revision, global ABI, schema, closed contracts/capabilities
and the independently computed App7 descriptor. A lookup is neither a new
repository authorization nor executable admission, permission, activation or
health.

`View::new` borrows the compiled banks and those separate owners. Both downloaded
views must refer to that same actual Images and Snapshot; logical B/C indices,
Kernel slots and digests cannot collide. A digest already in either compiled
bank is refused. The View owns parsed index metadata borrowing the separate
immutable image owner, so there is no self-reference, static cast or heap.
Registry still independently checks exact pointer and length before cache reuse
and applies current compatibility. The measured metadata footprints on x86-64
are 592 bytes per Downloaded and 1,192 bytes per two-slot View. No State or
Controller field/BSS allocation is added by this mechanism. A future wired
caller still requires its actual linked stack/image census.

Construct this view only within the scope of a State operation. Use
`active_source`, `prepare_source` and `admit_source` for downloaded identities;
`open`, `metadata`, `commit`, data, Note and grant operations accept `Sources`.
Keep the compiled bank object for initial `install`, bundled launch and the
existing System recipe. Dropping a view before a mutable Images operation is
required by Rust borrowing; this cannot release the Kernel's physical RO lease.

Data and Note authorization re-resolve the actual session package. Remembered
policy still binds its original exact package and cannot silently grant access
to a downloaded replacement. Existing blank-only namespace formatting, durable
readback, uncertainty fences, original Store intents and one actual Backend
owner are retained. App registry `previous` is not System/health KnownGood.

Tests use actual signed public B/C fixture bytes, a modeled Images syscall
adapter, and the actual Registry/Store/Data/Note/grant implementations. Their
synthetic prior lifecycle state and clocks establish no guest execution,
physical mappings, qualified provider or health. Actual acquisition, downloaded
activation/health and same-disk offline rollback remain integration gates.

Cold startup must restore content before the first App registry open. Existing
`State::take_content_backend` already works directly after `State::new`; it does
not require opening a registry. Authenticate the actual content arena, retain
its typed Snapshot through consuming extraction, return the identical Backend,
seal bytes read from its actual persisted object, build View, then call
`State::open(&view)`. A prior bank-only open of downloaded metadata correctly
fences/refuses and must never be cleared or treated as missing/format permission.
Extracted Snapshot is retained local identity, not a new remote decision or
permission to bypass current-head/floor checks.

A same4MiB-disk model follows this order through the actual content and native
Block adapters. Signed B is persisted, registry/data/Note are committed, the disk
is cold-reopened, and the actual stored object is read into the modeled Images
seal. Saved value2077 and Note remain available. This closes the library
composition test; actual Controller mount ordering and guest execution still
require wiring and evidence.
