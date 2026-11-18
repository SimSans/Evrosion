# ADR-0045 — Scoped File/Object service

Status: Accepted
Date: 2026-10-27
Owners: Project owner; storage and userspace service maintainers
Related: ADR-0037, ADR-0040, ADR-0043, ADR-0044; E-008; E-010; E-025.36–44

## Decision

Put the first application File/Object boundary in a source-built userspace
service, backed by the existing exclusively owned `ev-store` and separate block
driver. Keep the kernel responsible for actual capabilities, mappings, protected
calls, scheduling and retirement. File methods, object policy, client counters,
volume operation allocation and storage formatting remain userspace decisions.

The Internal implementation serves one stable logical Object1. Its two distinct
Endpoint objects bind immutable read and read/replace policy. The server selects
the binding from the capability it actually used for an authorized receive;
the request has no object, endpoint, volume, sector, generation or global journal
ID selector. A number in the gateway library is not kernel authority. The actual
receiver route, thread/domain and live RECEIVE/CONTROL grant are checked by the
kernel before delivery.

The generated logical protocol is a canonical 256-byte frame: 32 bytes of header
and at most 224 bytes of payload. Methods are Read and Replace; counters use the
full u64 field. Unknown versions, methods, reserved bytes, invalid lengths and
Replace counter0/MAX refuse before backend I/O. Read-only Replace and unknown
receive bindings likewise refuse before backend access. This small Object1 and
payload bound is an explicit bringup profile, not a permanent filesystem or
consumer file-size limit.

## Durable logical retry

Persist the user payload and its LAST logical receipt together in one atomic
WriteMutable. The internal `EVFILE01` envelope contains magic, version1, exact
payload length, reserved zeros, per-object client counter, server-selected global
Store operation ID and payload. Initial counter/op0 means no mutation receipt.
There is no automatic migration from legacy plain bytes or malformed envelopes.

For a new replacement the client counter must be exactly current+1. Only then
does the service obtain `Store.next_operation()` and publish the complete
envelope. The application never chooses the global volume operation ID, and the
application response exposes only its logical counter and replay result.
Malformed, read-only, zero/MAX, skipped, stale and conflicting requests do not
consume global IDs. An identical current nonzero counter and exact payload
returns the retained receipt without Store.execute or another write. This works
after cold reopen and after the bounded volume journal has reused the original
global receipt slot.

Retention covers the LAST logical receipt. It does not promise unlimited
exactly-once history: older counters are stale, a changed current payload
conflicts, and neither counter wraps or resets silently. Valid authorized
successive replacements still consume durable operations. An I/O error may have
committed; stop/idle/reopen the backend and retry the SAME logical counter and
payload rather than substituting a fresh counter.

One Store owner serializes all volume writers. A shared buffer mapping or lease
alone cannot establish physical-region exclusivity. The actual experiment uses
one server/device and reaps each old VM before reopening the disk.

## Actual authority and buffer lifetime

The server receives separate Memory Objects for the block window at user page508
and application window at507, block Endpoint SEND, and the two File Endpoint
RECEIVE/CONTROL grants. The application receives only its page507 Memory grant
and SEND on the two File endpoints. It never maps page508 or receives block,
ports, volume, image-selection or generation authority. Only the driver receives
the scoped ATA IoPorts grant.

File routes begin unbound. After control read and Store initialization, the
server explicitly self-binds both actual receiver capabilities through existing
BindReceiver21. The kernel derives the running thread/domain and validates the
exact live RECEIVE/CONTROL grant. An actual early application call is denied
before reservation, queue acceptance or wait. `EVFEARLY` and `EVFREADY` sequence
this closed fixture; neither readiness advertisement grants authority.

The server copies the complete request into private 256-byte storage before
decoding policy or making nested block calls. Actual application→File→block
calls retain protected origin, parent, trace and deadline, with at most two
pending reservations and depth2. Replies use the actual serving thread, receive
endpoint and received nonce, and wake only the matching protected caller.

This first shared-buffer profile excludes admitted timeout/cancellation, as in
ADR-0043. The fixed controller stop precedes every admitted call deadline, and
the sole caller remains blocked until an actual reply or verified stopped peer.
General timeout-safe buffer reuse requires a separately enforced ownership or
mapping transition; the File codec or a completion boolean cannot supply it.

## Verification and measured limits

The two-VM File/Object execution (local engineering archive)
is PASS for this bounded BSP/AP-parked Q35/TCG/OVMF profile. One retained kernel,
boot image and measured server/app/driver cohort serve two fresh VMs. The write
phase records 11 outer calls and 41 backend calls, including 18 calls nested
after actual outer delivery and no calls nested before delivery. It completes
11 backend write/flush mutations. Cold Verify records seven outer and 19 backend
calls, including two delivered nested calls and zero mutations. Actual blocks,
wakes and replies match all 52/26 accepted calls.

The app actually observes read-only, malformed, invalid/skipped/conflicting
counter and duplicate outcomes, denied port access and denied backend use. The
kernel independently records one early unbound-call denial, two self-bindings,
four actual mapping leases and protected nesting. At the private-copy checkpoint
it overwrites the shared application frame while the actual app is blocked;
the original B payload must still be published and returned. The distinct block
frame and guard bytes remain untouched.

Independent host observers open only read-only raw sectors and verify exact
envelope counter1/globalop1, committed receipt sequence2 and B payload. They
attempt no writes or flushes. PendingA remains unresolved with no admission,
KnownGood or failure capsule invented for this interface proof. Every disk byte
is unchanged during cold Verify after its control sector is set. Resources,
leases, mappings, inactive images and metadata all retire successfully.

The first cleanup failure (local engineering archive)
remains immutable evidence. It validated an actor mapping using revoked
authority after stopping the actor. Corrected teardown still requires exact
wrong-object refusal and actual Revoked authorization denial, then releases the
retained physical lease after quiescence. No capability check was relaxed.

Server/app each declare 2048 CPU ticks, 32 frames, one process and one thread;
the world has 2048 elapsed ticks, a 4096-tick ancestor budget and 100000 transition
bound. Measured write/verify usage is 639/407 ticks, equal to the sum of actual
driver/server/app CPU and the ancestor charge. Maximum pending remains2.
The server/app consume 25/19 admitted frames and each explicitly declares a
guarded 16KiB RW/NX stack. Linked concrete stack paths measure 11368/3208 bytes
including return-address allowances. They are not formal whole-call-graph upper
bounds: precompiled panic/format helpers lack stack-size metadata. Actual loaded
text/data bytes match the measurement probes; no kernel stack was increased.

Nine gateway model tests additionally cover interruption/recovery at backend
boundaries, full/empty payloads and receipt survival beyond journal reuse.
Generated codec, role-admission and host parser/raw-observer tests cover canonical
framing, counter overflow, malformed diagnostics, corruption and repair refusal.
Those model checks are distinct from the linked physical execution above.

This decision supplies the first scoped File/Object interface required by
E-025.36–37. It is not a general filesystem, arbitrary multi-client service,
consumer desktop, production disk power-loss certification or whole-M3 PASS.
Owner-operated recovery and the combined current-source acceptance gate remain
separate obligations recorded in M3 progress.
