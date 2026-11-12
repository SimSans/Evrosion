# Durable grant policy

This bounded `no_std` bridge persists explicit per-owner application READ policy
with the existing Store transaction engine and picker intent format. It does not
persist handles or grant capabilities by parsing records. **A-003 remains open**
until real trusted consent, durable publication, cold fresh-capability delivery
and revocation execute together in the Native system.

One scoped latest slot contains a canonical 256-byte Empty owner/App header or an
existing `ev_picker::intent::Record`, including revoked tombstones. Remember,
revoke and regrant use increasing policy revisions and actual Store operations.
Each Store operation publishes exactly one policy revision; stale records under
new operation IDs and System boot/health metadata are refused. An active policy
must be revoked before replacement. Package and File object/
revision/content remain pinned; current File permission revision 1 is explicit and
separate from the changing durable policy revision. No mutable external File
permission database is admitted by this first profile.

`PolicyOwner` exclusively owns a scoped `SectorIo` device. `with_open` permits the
Native State's one backend/window owner to lend that device for one operation.
`prepare_remember` requires a genuine library-created `ReadDelivery`; the trusted
integration remains responsible for actual consent provenance. `publish` retains
its move-only intent before writing and requires exact readback. Any uncertain
operation fences subsequent work until `resume` resolves the same operation as
unpublished or committed. Conflicting later heads return the real device and
pending intent. No automatic reformat or transport retry occurs.

Cold `remint` reads the authoritative latest slot, checks current owner/App/
package, current policy revision, live incarnation and File identity/revision/
readability, then invokes `FreshReadHandoff`. That callback must recheck actual
ProcessCONTROL, source capability, managed inbox and request provenance and
perform real capability delegation. `Eligible`, a digest or a model ticket is
never authority or a successful runtime delivery receipt.

The `consent` module parses one complete explicit owner response against a
displayed canonical action. Its public token is correlation metadata, not
authentication. Actual prompt presentation, pre-arming input drain, trusted
channel and clock provenance remain the SourceRoot adapter's responsibility.
Revocation confirmation hashes a separate action domain and exact latest policy.

The current component tests exercise real Store/Picker code with modeled handoff
callbacks, cuts at every publication read/write/flush boundary, uncertain reply
resolution, stale/conflicting heads, tombstone cold reopen/regrant, subject/
resource negatives, complete-input binding and scoped owner retention. First
namespace allocation is deliberately separate: partial formatting fails closed
and preserves bytes; it is not claimed to have journaled old-or-new availability.
Checksums are integrity checks, not hardware protection against whole-disk replay.

Native integration is staged separately from this library. The coordinated next
profile includes recovery's 22nd Root role and a separately admitted grant-policy
Store region; no disk map, bootstrap ABI, Root runtime or selected-file mechanism
is changed by this crate. Existing selected Picker delivery must never be faked
to satisfy cold remembered access. The fresh generic managed READ path and actual
UI/owner-action pending states require their own implementation and VM proof.

See the canonical [identity taxonomy](../../architecture/designs/IDENTITY_TAXONOMY.md)
and [selected-file approval boundary](../../architecture/designs/PICKER_APPROVAL.md).
