# Resident document engine

Internal no_std engine for the selected M8 desktop. The caller owns a resident
buffer of at most1MiB; it is never returned as a stack value. The engine preserves
valid UTF-8 bytes, bounds scalar selection/navigation and atomic insertion,
replacement/backspace, and provides bounded viewport copies. It does not
normalize line endings or silently repair invalid input.

Dirty means edited since the last confirmed open/save; returning text to the
same bytes still remains Dirty until a verified save. This avoids hashing1MiB
on each keystroke. Revision conflict blocks same-file Save; read-only revocation
blocks edits. Local conflicted bytes remain available for explicit Save As.

A Save freezes the proposed revision, full length and SHA-256. Begin and every
ordered4096-byte chunk must echo the exact transfer facts. A Commit receipt
alone does not mean Saved. Independent streamed readback must have the exact
revision, offsets, bytes, length and digest, including an actual empty read for
an empty file. Only then is the engine Saved. Unexpected delivery/completion
keeps the immutable proposal and freezes edits/new Save until independent
recovery. Close then requires recovery; Dirty close requires explicit discard.

The operation number is a caller correlation for BeginSave, never the backend's
trusted global sequence or the transfer identity. A native client must allocate
fresh distinct File2 operation nonces per mutating RPC and retain them across
uncertainty; equal nonces from different callers must remain distinct.

Deliberate Save cancellation is allowed only after Begin, between settled
prepublication requests. The engine retains the frozen proposal, stage token
and exact Abort operation through AbortReady/AbortSent. The native owner issues
one File2 Abort under the original whole-transfer cut and requires exact
correlated success with its real loan returned before restoring Dirty. Busy,
other refusal, malformed response, expiry or uncertainty never clears staging,
retries Abort, renews a cut or becomes Saved. CommitSent/readback cannot roll
back through cancellation. Bytes, caret and the committed base revision stay
unchanged. A subsequent Save requires a new explicit action and nonce.

The native Editor presents Cancel in the fourth toolbar slot while cancellation
is available; its semantic node19 has the same label/action. Dedicated existing
Activate intent9002 means cancellation only and can never fall through to Close.
Root's direct keyboard routing is integrated and qualified separately; a copied
ID supplies no focus, input witness or authority. An old accepted Cancel label
continues to mean cancellation if processing is delayed past Commit.

The engine owns no capabilities, mapped loans, actual transport, renderer or
semantic provider. The native adapter must supply authenticated replies from
the held exact-object route and independently established loan/quiescence facts.
`rejected_before_delivery` is only valid after a proven pre-delivery refusal with
the loan returned; it is not an uncertainty escape. No model test proves guest
authority, persistence, responsiveness or runtime resource acceptance.

Focused host tests include a full1MiB save/readback, wrong transfer/revision/hash,
reordered/corrupt readback, uncertainty at each phase, UTF-8 boundaries, empty
files, atomic quota refusal, revocation/conflict and edit-counter exhaustion.
Bare target check and strict component lint are recorded in the M8 task receipts.
