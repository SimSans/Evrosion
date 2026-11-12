# Durable application-registry publication core

`ev-app-registry` is a bounded, safe `no_std` publication library. It connects the
existing immutable `.zion` package API and lifecycle `Record256` to one exclusively
owned StoreV2 mutable object. It is not an installer, executable loader, grant
broker or hardware acceptance result.

The trusted installer supplies its canonical AppId/host context, actual immutable
package containers and one whole14-sector backend. Complete containers are fully
parsed and hashed before use. A resolver may retain an immutable parsed view;
reuse requires the exact same backing pointer and length as its resolved bytes.
Other resolvers still parse on every use. Load, preparation, publication and
recovery always check current compatibility, identity and stored VersionRef/schema.
A package's claimed identity or
requirements never create namespace ownership or permissions.

`format_new` is explicit blank-only allocation. `open` recovers and validates.
`expected` binds revision, canonical record, host context and next global operation.
`prepare` computes a move-only intent for Install/Stage/Activate/Replace/Rollback/
Remove/Reinstall; Replace combines Stage+Activate in one durable operation and
advances lifecycle revision twice. `publish` revalidates packages, uses exactly
that operation ID, and adopts the new snapshot only after exact readback. Tombstones
retain identity/data epoch; incompatible reinstall/rollback refuses.

Any execute/readback uncertainty retains the original intent and latches recovery.
The owner extracts the actual backend and intent, independently stops the previous
writer and restores the transport, then explicitly resumes. Exact recovered record
and operation high-water establish committed or unchanged publication; an unchanged
base returns the same-ID retry permit. An IO error alone proves neither execution
nor nonexecution. Rejection returns the actual backend and unresolved intent.

Important limits:

- One live writer owns the entire region. A copied endpoint or another backend
  alias does not establish exclusion; real integration must enforce it.
- `Prepared` survives recovery only while retained by its actual owner. The API
  does not serialize a request across a dead guest; physical cold retry requires
  independently retained, checked intent or a verified journal replay protocol.
- `DataMigrated` is an assertion by the trusted actual data owner about an already
  committed migration, not permission for an App to invent an epoch. There is no
  migration implementation or cross-region atomicity claim here.
- Store payload remains exactly256 bytes. Store root/journal envelope capacity
  does not allow an arbitrary larger mutable object.
- `region` contains a proposed bounded NativeSystem address translation and one
  mutable-backend reborrow. It confers no Block authority and is not wired into
  the current desktop backend, whose accepted ranges remain unchanged.
- Initial enclosing Store generation is Pending/KnownGoodNone; formatting registry
  metadata does not fabricate generation admission or boot health.

`app_data::AppDataEnvelope` is separate immutable256-byte metadata: canonical
AppId, fixed schema epoch, monotonic counter and u32 value with canonical reserved
zeros and a checksum. `initial` counter0 is not a stored-write receipt;
`checked_replace` requires exact expected identity/epoch/counter and never changes
the epoch or wraps. Encoding/decoding performs no I/O and supplies no migration or
namespace authority. A model test persists it in a different Store region and cold
reads it back while retaining actual registry model bytes as guards; physical data
ownership and disk completion are still separate integration obligations.

Tests use real Store codecs and immutable package parser with model devices,
including IO cuts/cold reopen, stale heads after journal reuse, package/identity/
ABI/schema substitution, partial-format refusal and other-region byte guards.
Host and no-std checks establish portable behavior only. Real executable/process
quiescence, default grant revocation, immutable RAM mappings and physical disk
verification are separate work.
