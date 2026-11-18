# ADR-0110 — Native workspace clients and actual self identity

Status: Accepted Internal Level B refinement; VM qualification pending.
Date: 2026-11-16
Related: ADR-0104/0105/0106/0108/0109; M8-03/04/05/07/11.

## Actual self query

Add M8-only scalar `SELF_IDENTITY = 59` and `SELF_IDENTITY_INFO = 60` without
changing an existing syscall number or bootstrap encoding. INFO requires four
zero operands and returns descriptor `0x0000000100030001`. Its separate contract
hash is `1c8299e7b01d2653d2dc2c3f2d573fae78f73bdc91283b1aacb640f79f305b9f`.
QUERY selects field0,1 or2 in RDI, requires zero RSI/RDX and preserves compiler
live R10. The fields are the actual process identity, actual thread identity
and registered immediate incarnation number or zero. Results clear RDX.
Unsupported profiles retain their unsupported operation behavior.

The Kernel obtains the current thread and domain from captured execution. The
exact generational thread/process/Job association must be registered and live,
and the thread must be Running. There is no caller-supplied identity to query.
A zero result for the optional incarnation is valid. All children can share the
captured Root incarnation; this field alone never proves that a caller is Root.
Root-only services instead verify the exact registered process/thread pair from
the ServingOrigin receipt before reading shared bytes.

## Native client custody and selection

The internal no_std SDK owns an admitted two-page File2 window and the received
SEND handle. Control is256 bytes in the first page; bulk data is at most4096
bytes in the second. Full64-bit request IDs survive scalar RPC. Each mutating
RPC gets a distinct per-route operation nonce; transfer identity and trusted
backend sequence remain separate. A malformed reply, accepted work, uncertainty,
stale/corrupt result or transport ambiguity retains the exact request and fences
further traffic. Reconstructing a client on that same route is not recovery.

Root installs Selection metadata only after binding the authenticated target
route. It contains dataset/object identity, access, revision, length, digest,
name and the receiver/request correlation; none of these integers is a handle.
The app compares the actual Inbox nonce, actual self process/thread/incarnation
and received SEND capability before using the selected window. An ordinary app
does not obtain edit rights from a filename, layer label or Selection bytes.

An already bound Editor must explicitly pause before another Selection. A
monotonic `ReleaseFile` request closes its local quiescent SEND handle and stops
all FileWindow access. `Released` is only a protocol acknowledgment. Root must
independently retire the old kernel grant branch, drain retained loans and
reconcile the Workspace route and durable staging before rebinding that window.
No cooperative acknowledgment, logical route revoke or PID reuse is a physical
quiescence proof. Accepted/uncertain saves refuse this release shortcut.

## Editor behavior

The actual native Editor borrows a separately loaded1MiB resident buffer. It
validates opened bytes through chunked reads and full SHA-256 before exposing
text. Bounded UTF-8 selection/navigation, insertion, viewport and scrolling
preserve exact source bytes and line endings. The initial bitmap font displays
unsupported glyphs as placeholders without rewriting their UTF-8 bytes.

Save freezes the proposed destination revision, full length and digest. Begin,
ordered chunk acknowledgments and exact Commit receipt are followed by an
independent complete readback, including a real empty read for empty files.
Only then does the app report Saved. A timeout preserves the buffer/proposal and
reports recovery required; no fresh nonce silently retries uncertain work.

Save As keeps resident source bytes while the old route is paused. Only after a
fresh independently authorized writable destination is installed can the engine
retarget its expected revision and the client start the new route's counters.
It then performs the same complete save/readback. Read-only source access does
not authorize overwriting another object. Dirty close needs explicit discard;
pending/uncertain work needs independent recovery.

Native Files uses the same SDK's separate namespace link, with independent
operation IDs, authenticated dataset correlation and retained uncertainty. It
does not accept unsolicited File grants or use the namespace window as a preview
route. Root's protected selection is a separate authorization step. Actual guest
grant/input/view correspondence, accessibility and recovery remain open gates;
the SDK, renderers and component tests are not their acceptance evidence.
