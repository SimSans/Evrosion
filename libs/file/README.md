# Bounded logical File/Object gateway

`ev-file` is a safe no_std/no_alloc userspace library over one exclusively owned
`ev-store`. It is a first logical service boundary, not a kernel filesystem or a
complete multi-object filesystem. The initial object is stable Object1. The
trusted receiver binds two immutable actual RECEIVE handles to read and
read/replace policy; clients cannot name an object, sector, global journal ID,
volume or generation. Kernel receive validates actual capability lifetime and
authority before the service chooses a binding. Constructing a number in this
library does not grant kernel authority.

Logical wire frames are256 bytes:32-byte canonical header and at most224 bytes
of user payload. The generated codec validates all lengths, reserved fields,
methods and fullu64 counters before backend I/O. Read-only Replace, unknown
receive routes, counter0/MAX and malformed frames cannot read the backend.
Transport must retain/exclusively sequence shared memory; the first fixture
excludes admitted timeout and takes a private server request snapshot before I/O.
A CallId, timeout, codec result or receipt alone is not a buffer-release proof.

The stored file is a single atomic EVFILE01 envelope:8-byte magic, versionu16=1,
payload_lenu16,4 zero reserved bytes, counteru64, server-selected global volume
operationu64, then at most224 user bytes. Initial counter/op0 truthfully means
there is no mutation receipt. Clients may read this state but Replace0 is
malformed. Later counters and global IDs are nonzero/notMAX; encoding consumes
exactly32+payload_len bytes. Legacy plain bytes, unknown versions, malformed
metadata and invalid stored receipts refuse without reformatting data.

For Replace the next client counter must be exactly current+1. The server obtains
`Store.next_operation()` itself and atomically publishes payload, counter and
global receipt in ONE WriteMutable. No in-memory receipt table is needed. A
repeated current nonzero counter with exact payload equality returns replayed
without Store.execute or any write, even after the global journal wraps and the
service restarts. The global ID stays inside the trusted service/envelope;
client responses expose only the per-object counter and replay status.

Retention is explicitly bounded to the LAST logical receipt. Lower counters
are stale, skipped counters reject, same-counter different-length/content
conflicts, and no counter wraps or silently resets. This is not unlimited
exactly-once processing. An I/O error may have committed: explicitly stop/idle
and reopen the backend, then retry the SAME counter/payload; never automatically
substitute a fresh counter. All volume writers must serialize through this one
owner; owning a shared transfer window alone is not volume exclusivity.

Nine portable tests cover cold read/replay, global-vs-logical ID separation,
receipt survival after12 unrelated volume checkpoints, exact payload conflicts,
stale/skipped/MAX rejection, zero backend I/O for authority/syntax denials,
every read/write/flush/torn replacement boundary, interrupted recovery, full224
and empty payloads, and invalid stored receipt refusal. Generated codecs add
total arbitrary decoding and canonical framing tests. These are models, not
actual File service/grant or hardware acceptance; physical actors are separate.

The additive `desktop` module binds two disjoint volume-local Object1 owners to
four fixed Notes/Private RO/RW endpoints. `DesktopGateway` keeps the existing
per-object counter/receipt rules, and `MetadataQuery` reads actual stored counter
and SHA-256 payload words through the selected RO endpoint without an App buffer.
See [desktop storage integration](../../services/block/DESKTOP_STORAGE.md).
The original one-object gateway and generated File-v1 framing remain unchanged.
