# ADR-0105 — Versioned workspace and larger-file contracts

Status: Accepted Level B implementation refinement; codec/model qualification only.
Date: 2026-11-15
Related: M8-01–04/08/09/11; ADR-0102/0103/0104; E-008/E-009/E-010/E-014/E-015/E-016/E-019/E-023/E-026.

## Problem and preserved boundary

The accepted File-v1 codec carries one 224-byte logical Read/Replace object in
a 256-byte frame. Notes/Private identity and read/edit authority come from actual
receive routes, not names or packet selectors. Arbitrary object allocation,
directories, larger data, multiple writers and interruption-safe namespace work
are new M8 requirements; raising v1's payload or treating names as authority
would change its existing meaning.

Keep the old schema, generator, binding, wire bytes, stored envelopes, exact
READ/edit separation and historical evidence unchanged. New workspace metadata
does not reinterpret a legacy volume or serialize a live grant. Durable remembered
READ policy remains separate from incarnation-only edit authority. Original
volumes are preserved; data migration requires its own explicit implementation,
rollback window and copy/interruption qualification.

## Decision

Add two **Internal**, separately versioned contracts before their actual actors:

- `ev.internal.workspace@1`: Inspect, revision-pinned one-row List, Create,
  Rename, Move within the scoped dataset, Trash, Restore and QueryOperation.
- `ev.internal.file@2`: revision-pinned chunk Read, BeginWrite, WriteChunk,
  Commit, Abort and QueryOperation. The actual File endpoint fixes the selected
  object and available rights; there is no wire object/volume/sector selector.

The JSON schemas specify fixed little-endian 256-byte control layouts, typed
opcodes/outcomes, exact field offsets, canonical zero padding and transport
meaning. The closed generator rejects unknown/missing/duplicate declarations,
wrong types, booleans or floats replacing integers, changed bounds or weakened
authority/ownership semantics. It renders all bindings before writing any; a
bad final schema cannot partially publish an earlier contract. Rust bindings
are generated and contain no allocator or unsafe code. These are intentional
language-neutral layouts, not a compiler-private Rust ABI or a Stable SDK.

Workspace object identity is `(actual route's dataset, slot:u16,
generation:u64)` with 256 child slots plus implicit root in this reference; finite nonzero generations
prevent accidental slot reuse from naming the old object. Slot 0 is root,
whose metadata has self parent, directory kind and empty name. Other names are
1–96 UTF-8 bytes, exact byte comparisons, without control characters, either
separator, `.` or `..`. No Unicode normalization or case folding is implied.
Dataset identity is a nonzero 16-byte descriptive identity returned by the service.
Child slots are1–256; root is0/generation1. Listing cursors include256 so the
last child and end position remain representable. The first codec incorrectly
treated256 as exclusive; real backend integration corrected that boundary while
keeping the256-user-entry target and legacy codecs unchanged.
Listing, identity, names, hashes and metadata confer no authority. Server route
and actual authenticated caller must authorize every source and destination;
listing a directory does not authorize opening or modifying every child.

Expected namespace revisions pin enumeration and mutations. List returns one
entry and an advancing bounded cursor, or End at that same namespace revision.
Rename/move preserve identity. Trash is reversible namespace state, not implicit
purge. Reclamation and generation reuse must respect all old grants, readers,
stages and outstanding device/shared-memory ownership. Codecs validate shapes;
only the actual service/storage owner can enforce these lifecycle properties.

## Larger files, staging and exact confirmation

The first File@2 reference bounds complete content to 1 MiB and each independent
MemoryObject/shared-window data loan to 4096 bytes. Those are reviewed Internal
profile bounds, not permanent architecture limits. The control frame contains
offsets, lengths and SHA-256 values, never pointers or inline document bytes.

BeginWrite states the exact current revision, full length and full digest;
the service reserves staging capacity without exposing partial content.
WriteChunk supplies an opaque transfer token, ordered offset/length and exact
chunk digest. The actual service copies privately before I/O, verifies bytes,
checks stage offset/remaining length and records durable progress. The storage
implementation's stage information remains independently authoritative.

Commit repeats the transfer, full length/digest and expected prior revision.
Its successful response must match request/operation IDs, transfer, exact full
length/digest and revision `expected + 1`. The service checks those declarations
against actual retained stage information and atomically publishes complete
verified content. A client reports Saved only after this durable commit and
separate readback of that same revision/content. Read replies bind exact revision
and offset, bounded returned length and a digest of the separately owned range;
the adapter must verify that digest against the actual bytes. A wire hash alone
does not prove that storage or data transfer occurred.

The receiving endpoint and actual caller bind both the object and transfer.
Client operation IDs correlate only that actual requester/route; the service
binds the authenticated endpoint, caller incarnation, lease, operation ID and
canonical original request fingerprint, then maps them to its own trusted
serialized durable backend operation IDs. Two independent Editors may both use
operation 1; equal wire correlation never makes their identities interchangeable. A wire
transfer token is a scoped opaque token, never an unchecked backend stage/global
operation selector. No packet selects raw storage or supplies rights.

## Deadlines, failure and uncertainty

Each request has a finite, nonzero, non-maximum absolute monotonic deadline,
a nonzero request serial and, for mutations/query, a nonzero operation ID.
Read-only requests carry zero mutation ID. The adapter checks the actual
monotonic clock, one-outstanding-operation admission, authentic sender identity,
routes, queue bounds and capability counts. Codec construction is not an actual
deadline/wait/identity check. Control messages carry zero capabilities; the bulk
loan must already be explicitly bound and retained by its real owner.

Completed is distinct from Accepted and Uncertain. Denied, Conflict, NotFound,
NoSpace, Busy, Unsupported, Cancelled, Corrupt and Stale are typed results; End
is specific to namespace enumeration. Negative results never contain success
payloads. After acceptance, an I/O failure or missing completion that does not
establish the exact outcome must be reported/reconciled as Uncertain. Timeout
ends waiting; it neither proves nonexecution nor undoes a write.

The File pending model retains one exact request and its uncertainty through
timeout and rejects mismatched/late duplicate correlation. It cannot return a
real memory loan by itself. Actual mappings/buffers and the proposed immutable
payload remain fenced until matching authenticated completion or independently
proven quiescence. Abort is cooperative and cannot retract an already committed
revision. A service must not fabricate Cancelled from deadline expiry.
An original-request Stale or Corrupt result also retains Uncertain state: a
missing bounded receipt is not proof that an earlier write never executed.

QueryOperation reconciles the same requester-scoped ID; it is not reexecution or
an indefinite exactly-once ledger. The implementation must use separately owned
bounded control state for reconciliation when a bulk loan remains quarantined,
or wait for the actual ownership recovery path. It must not overwrite an old
shared control/data frame merely to issue Query. No client helper automatically
allocates a fresh mutation ID or retries a timed-out mutation. Identical replay,
conflicting reuse and retention/stale rules must be enforced by the real service
and storage receipt mapping, with the bounded ledger/retention policy explicit.
A File Query completion can report the exact stage's declared full length/digest
and durable written-prefix offset with zero data length; it does not return a
newly granted loan or authorize resumption by itself. A later caller operation
must not silently turn an evicted receipt into proof of nonexecution. Where the
bounded retained history cannot establish the exact outcome, report Stale or
Uncertain and retain the explicit recovery/fencing requirement.

## Alternatives and resource effects

Widening File-v1 silently breaks old semantics. Names or wire slot numbers as
authority violate capability routing. Copying 1 MiB into every stack/control or
semantic snapshot violates bounded transfer and resource goals. Exposing backend
sectors/global operation IDs couples the public boundary to storage layout.
Separate versioned controls and bounded loans preserve the existing mechanism
direction without inventing another authority or lifecycle system.

These codecs add no running process, privileged primitive, capability right or
automatic resource-budget increase. Actual admission, handle/frame/image/stack
budgets, chunk-window lifetime, repeated retirement and contention remain M8
integration work. The new backend and dataset live in their own explicit scope
under ADR-0104; this ADR does not format, mutate or migrate legacy data.

## Qualification and remaining work

Retain generated-binding checks, adversarial schema tests, malformed/truncated/
reserved-byte control tests, exact response-correlation tests, uncertain pending
state tests and both-direction legacy-version refusal. Test failures and command
receipts remain under the isolated M8 task directory. The first Rust run found
a test incorrectly treating valid low Read offset bytes as reserved; the test
was corrected while preserving the accepted wire range and failed output.

Host tests and code generation are not M8 actual grant, RPC, storage, shared-loan,
device retirement, recovery, accessibility or VM acceptance. Actual adapters must
still enforce sender/route rights, request replay policy, per-requester-to-backend
ID mapping, exact stage checks, buffer quiescence, corruption/refusal behavior,
File/Block death and timeout, VM cuts during staged Save/namespace publication,
and cold independent verification. Qualify saved 0.2/0.3 compatibility and failed
App update recovery on preserved copies. Physical qualification, general Root/
Kernel image replacement, official signing/publication and consumer migration/
bundled Windows support retain their accepted separate scopes.

Review this ADR before expanding bounds, promoting maturity, adding persistent
edit grants, changing names/revision/conflict semantics, introducing new data
transports or claiming that a host codec result closes an actual integration gate.

### M8 gateway and native implementation refinement

The isolated `services/workspace` gateway now implements both generated
protocols over the actual Dataset. Namespace bindings fix a directory generation
and metadata-management rights; List includes reversible trash state and returns
one actual entry/cursor at the expected namespace revision. Restore uses the
backend's single atomic `restore_at`, preserving exact destination/name/expected
revision and avoiding an observable restore-then-move intermediate state.
Namespace authority never supplies a File endpoint, content access, purge or a
ReclaimFence. Permanent removal/reuse stays refused pending actual Root lease
revocation and quiescence proof.

Client mutation IDs remain independent of global durable IDs in both protocols.
Each trusted bind freezes the current monotonic durable `next_operation` into
the backend lease scope. After a prior mutation, that scope cannot repeat when
cold kernel diagnostic IDs, Root epoch/lease and client nonce1 repeat. Exact
original frame/content fingerprints and the bounded latest receipt distinguish
replay from conflicting reuse. Unknown execution retains original private
proposal/frame, global mapping and deadline; repeated admission after that
deadline remains retained, never a fabricated Cancelled result. Cross-protocol
writer fencing prevents fresh effects after an accepted unknown publication.

The optional native actor uses V5 child528/role16 Root-only control and independent
role10 Files namespace. Actual serving-origin57/INFO58 is negotiated and checked
before windows, without changing RECEIVE_RPC34 or interpreting its cleared RDX
as caller identity. Root-bound File routes compare captured process, immediate
registered token (explicit0 allowed), thread and lease; packet identities grant
nothing. Role16's independently admitted sole Root SEND is the Root anchor, not
first packet contents or a shared cohort token. Successful Root Bind publishes
strict SDK Selection from actual bound metadata before Applied and independent
capability handoff. Root must first quiesce every use of that caller's window,
including Files namespace which shares its File frame.

The actor retains the actual RPC nonce and memory mapping through bounded
Commit verification and final publication, preserving the original inherited
deadline. Matching still-live origin is rechecked before completion publication.
Accepted uncertainty, cancellation/expiry or failed reply credit quarantines the
actor; no ordinary control returns a loan or manufactures new authority. Normal
open never implicitly formats or repairs; the separate NEW-only provisioning
image has a distinct prehealth phase. Host integration and bare executable/ELF/
stack preflight remain separate from actual V5 grants, RPC, timing, recovery,
device retirement and VM cut acceptance.
