# ADR-0114 — Native paged semantics and scoped actions

Status: Accepted Internal Level B refinement; native consumer qualification pending.
Date: 2026-11-16
Related: ADR-0102/0106/0108/0110; M8-05/06/07/11/12.

## Decision

Add `ev.internal.semantic-tree@1` (minor0/features0), the complete Internal A1
snapshot/action/range boundary. Its strict SDK codec is handwritten; it is not a
generated IDL or third-party stability promise. Host and actual Root package
requirements checks must consume the same SDK constants before admission.

Add Internal A1 semantic data over the existing selected Root control/events
channels. Preserve the sixteen-node tree bound by paging, with an independently
validated root on every page. Keep at most256 text bytes per explicit range.
The public SDK defines strict ordered eight-byte frames, complete immutable
snapshot publication, explicit abort/drain and bounded action/range requests.
Its [wire reference](../../libs/workspace-client/README.md) defines every field.
No Root bootstrap, File2 or old V1 wire layout changes through this refinement.

A native publisher captures only a complete accepted presentation. Root binds
the actual sender process/thread and provider incarnation/lease to the complete
model, view, accepted frame, mapping epoch and geometry. It stages all words,
then compares the full coherent actual Display tuple before publishing a tree
or text to an authorized consumer. A candidate is not publication. Revisions
remain64-bit; a skipped/coalesced native frame is not reinterpreted as sequential.
Large text and full96-byte names use distinct document/accessible-label range
kinds. UTF-8 data is preserved even when the initial bitmap font lacks glyphs.

## Authority and retained work

Root alone holds the consumer identity, current provider lease and READ,
ACTION or TEXT scope. IDs, tree values, a text range and a layer label grant
nothing. Root validates the target/action and current context before forwarding
an operation. The app validates Root's actual held channel and its own last fully
sent semantic snapshot against its current accepted presentation before acting.
Only advertised actions dispatch. Unsupported SetValue stays unadvertised.

Root owns keyboard/window focus; distinct assistive focus only navigates an
authorized tree. A painting action reports applied after the resulting actual
accepted Present. Root then requests a fresh snapshot for the changed state.
Open/Save As report requests, not permission approval, and Save retains its
independent exact durable readback requirement. Process close still requires
actual lifecycle observation and grant/window retirement by Root.

An uncertain or malformed stream remains fenced. Neither a new nonce nor a
new client instance on the live channel proves old work drained. Matching
explicit abort acknowledgment terminates protocol staging; it never undoes an
already applied action. Root retains each actual forwarded operation across
revocation/replacement until correlated completion or explicit drain. New
provider leases rotate snapshot nonces and cannot inherit old queued work.

Ordinary semantic Activate cannot approve protected access or an owner override.
The accessible protected-confirm route needs separate scoped authorization,
actual fresh owner-input custody, current challenge/view/provider identity and
single-use correlation through the same protected UI boundary. A payload cannot
supply an owner-input serial. That route remains a native qualification gate.

## Evidence limits

The SDK tests cover ordered publication, malformed/missing/repeated fields,
reserved bits, full-width revisions, UTF-8, geometry, stale nonce fencing and
explicit abort/backpressure. The native Editor publishes a complete nine-node
page and implements ranges, selection, scroll and file-action intents. Focused
host tests and bare-target strict lint are component evidence only. Actual Root
and Inspector consumers, Files and protected-root publishers, native rights/
revocation/provider replacement, usable scaling, and full keyboard/protected
confirmation workflows still require integrated VM evidence. No complete M8
gate follows from this ADR or the portable tests.
