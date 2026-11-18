# Bounded object transport

This module downloads only `/release/timestamp.bin`, `/release/snapshot.bin`,
`/release/targets.bin` and `/artifacts/hello.zion`. The same exact catalogue name,
destination, protected Client, socket and nonreusing Service port allocator remain
in use. Every file first closes the previous socket, observes Closed and a valid
lease and performs a fresh scoped Resolve/Query. The reference profile's
`example.org` answer is retained as a diagnostic; protected Connect always uses
the independently fixed allowed fixture IPv4 address. DNS cannot select or
broaden that peer. Lease loss refuses new work. Final cleanup can still
acknowledge actual Closed after a lease expires.

One download captures one absolute cut, at most65,536 PIT scheduling ticks. Its
at most2,048 attempted Client operations each retain the existing at most1,024
tick child cut. Explicit quiescent Pending responses defer the next operation
by64 ticks under that same original cut. Waiting, header and chunk acknowledgments
do not spend another RPC or renew time. This is a separate bounded object class:
256KiB already needs at least256 ordinary1KiB reads plus framing, control and
storage work. It changes no Hello, time proof, Stop, CPU quota or stack limit and
promises no wall-time delivery. Fragmentation can exhaust the bound and fail.

Metadata may have a bounded initially unknown length/hash, using exactly the
existing acquisition buffer limits. An artifact requires a supplied exact raw
length/hash, at most256KiB. Those values may come from parsed **untrusted** Targets;
matching them grants no publisher or executable authority. SHA256 covers every
raw body byte, including the complete Zion header. No bytes are zeroed for the
transport hash; current PackageId also hashes the complete raw package.

The caller retains one private4KiB chunk. `Headers` is emitted once, after bounded
canonical framing; it can accompany an already copied private body prefix. The
caller reserves its bounded metadata buffer or actual artifact Put, then calls
`acknowledge_headers`. A full chunk or exact final remainder is emitted once with
its offset. The caller copies metadata or completes actual `Put::write_chunk`
before `consume_chunk`. No further network RPC occurs while either acknowledgment
is pending. Prefix digests reject a swapped or changed private buffer. No shared
ClientWindow reference survives an RPC, and no full artifact buffer exists here.

HTTP permits a bounded200 response, canonical Content-Length and close framing.
It refuses redirects, ambiguous/duplicate headers, compression, chunked encoding,
overflow, truncation and extra body bytes. Exact EOF, every consumed chunk, the
full raw hash and actual final TCP Closed precede `Complete`. Stored bytes still
need content readback, independent release signatures, real qualified time and
durable replay/floor authorization through the acquisition coordinator.

Cancellation permanently abandons the download and can attempt ordinary socket
close only before its original cut. Clock regression, expiry and exhausted work
stay fenced. An accepted unknown Client response retains that actual Client and
window quarantine; cancellation cannot retry or release them. A failed Put/Arena
also remains with its actual poisoned owner. Neither Complete nor Cancelled is
NIC STOP or CPU-retirement evidence. The existing separately bounded hardware
shutdown and real retirement checks remain necessary.

The Host phase fixture contains public DEV material only, with freshly signed
metadata produced through the existing explicit private development authority.
Its author timestamps are untrusted to the guest. Only the artifact route has a
separate60-second Host response class, captured once at handler start; existing
Hello/time responses retain2 seconds. A B-to-C route switch selects immutable
public bytes for each accepted response and retains route/hash provenance.

Tests exercise the actual protected codecs, partial headers/writes/body, maximum
256KiB streaming through the real Store Put/seal/full readback, raw hash failures,
truncation/extra bytes, consumer credit, clock/counter fences, cancellation,
unknown quarantine, fresh DNS/lease restrictions and real owned TCP phase routes.
These are host/model checks. Actual integrated Root footprint, selected Kernel
census, download/commit/cold/retirement VM evidence remain separate gates.
