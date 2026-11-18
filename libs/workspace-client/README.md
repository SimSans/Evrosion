# Internal native workspace client

The no_std SDK implements File2 and namespace RPC over one independently admitted
two-page control/bulk mapping. It owns its request and mutation counters and
retains uncertain work. A transport timeout, mismatched correlation or malformed
response fences the window; constructing another client on that live route does
not return its loan or authorize a retry. QueryOperation needs independently
retained recovery control.

The optional File2 `Verify` method verifies one immutable staged chunk per
distinct finite request at the exact acknowledged prefix, before atomic Commit.
Its old-revision progress response is no durable receipt or Saved result. The
same actual route, transfer, expected revision, full length and full digest
must match throughout; uncertainty fences the original request and window.
The whole transfer horizon remains captured once and includes final committed
readback. See ADR-0119 for the measured single-Commit failure and compatibility.

File2 now declares additive minor1/STAGED_VERIFY bit0. New mutation clients must
establish actual loaded support before writable admission. Native Root probes
its actual Workspace and uses BindContract/Selection2 for such requirements;
producer/source metadata is not runtime availability or permission. Selection2
has distinct EVF2SEL2 magic and explicit major/minor/features. The new Editor
requires2/1/STAGED_VERIFY before constructing its File client and before Save.
Old Selection1 stays strict and unchanged; that Editor accepts it only for the
closed original File1 readonly projection. A malformed V2 never falls back and
feature metadata never widens actual route rights. See ADR-0123; new coherent
native SDK/negotiation qualification remains separate.

`NativeLink::from_admitted_mapping` is unsafe because address/length/handle
integers cannot establish actual mapping custody. Actual apps receive these
through a selected, measured loader and validate their exact startup roles.
`self_facts` negotiates read-only59/60 and queries actual captured self identity.
Selection metadata is strictly decoded and compared with the received Inbox
request and those self facts. Metadata carries no capability handle.

`close_quiescent` closes the client's actual local SEND handle only after its
request is settled. It marks the client closed before attempting that syscall,
so even an unexpected failure cannot restart traffic. It neither aborts durable
staging nor proves supervisor grant retirement, server quiescence or device
flush. The Root broker must independently establish those facts before reusing
the physical window for another object.

The UI codec supplies bounded Root control and app event messages, full64-bit
scene revisions, Inspector snapshot fields and explicit Editor release modes.
These intents do not authenticate ordinary input or authorize protected actions.
`Released` only means the cooperative actor stopped using its file window;
Root still needs actual Kernel and Workspace retirement receipts.

The actual native Files and Editor use these clients. Their host tests exercise
correlation, malformed replies, empty files, separate operation identities,
uncertainty retention, namespace changes and UTF-8 identity. Guest custody,
deadlines, service death, native accessibility and SDK reproducibility are
separate M8 qualification requirements.

## Internal A1 semantic transport

`ev.internal.semantic-tree@1` is the complete Internal A1 boundary, including
snapshots and operations (minor0/features0). The SDK constants are shared by
package requirements checkers. This handwritten codec is not generated IDL and
makes no third-party stability promise. `semantic` supplies paged, bounded data on the app's held Root control/events
channels. Every word is eight bytes: `41 01`, a little-endian field16 and word32.
A snapshot carries at most16 nodes on each of at most8 pages; it includes full
model/view/frame/mapping revisions, content geometry, focus/modal nodes, roles,
flags, supported action bits, UTF-8 labels and bounded text-range descriptions.
The root window repeats on every page. Labels hold64 bytes; full names use an
explicit accessible-label range instead of silently truncating96-byte names.

Root requests `8000|page` with a finite nonce32. The immutable ordered reply is
Begin0, header1..11, each node's32 words starting at16, then Commit7fff with the
same nonce. Fields12..15 and node reserved words are not extension space.
`Receiver::candidate` stages a complete validated tree. Root must still verify
the actual RootEvents sender/process/thread, current provider incarnation and
lease, full coherent accepted Display tuple and geometry before publication.
Wire identifiers and a tree snapshot confer no authority.

Malformed, expired, missing, duplicate or reordered words fence the receiver.
Fresh nonces never discard queued old work. Explicit Abort8008 and matching
AbortAck7ffe drain the snapshot FIFO before another request. Publishers advance
only on actual successful SEND; a full inbox retains exactly the unsent word.
Snapshot nonces increase per live provider stream and rotate on provider change.

`semantic::operation` defines a separate ordered18-word request:8100 Begin,
8101 kind/action/node,8102..8109 full model/view/frame/map,810a..810b text revision,
810c..810d offset,810e..810f argument,8110 snapshot nonce,81ff Commit. Actions are
Activate0, Focus1, Select2, Scroll3 and Expand4; SetValue remains unsupported.
Select packs anchor32 in the low and caret32 in the high argument, both exact
UTF-8 boundaries. Scroll is sign-extended i16; other action arguments and all
action offsets are zero. Only Select carries a text revision. Root owns actual
keyboard/window focus; assistive navigation does not implicitly change it.

A range request uses kind2 and action0 for an accessible label or1 for document
text. It has an exact text revision, offset64 and requested byte count1..256.
The immutable result is9000 Begin,9001 returned length,9002 node/kind,64 payload
words9010..904f and90ff Commit. Every unused payload byte is zero. A range starts
at a UTF-8 boundary and returns the largest valid prefix fitting the byte count;
EOF may return zero. No whole document belongs in a snapshot or service stack.
`RangeReceiver::staged_text` is not consumer publication: Root rechecks actual
provider/lease/view and READ or separate TEXT scope before releasing text.

9f00 is an applied-intent receipt;9f01..04 refuse unsupported/busy/stale/denied.
A painting action reports applied only after its resulting accepted Present;
Root then validates a fresh snapshot. File Open/Save As are intents that still
need Root's protected selection, and Saved still needs File2 commit/readback.
Abort81fe/AbortAck91fe terminate retained protocol work without undoing an action
already applied. Root retains the original forwarded operation through provider
revocation until a matching terminal or explicit drain; lease rotation alone
cannot erase queued native work. One operation is outstanding per provider.

Root keeps consumer identity, READ/ACTION/TEXT rights, provider lease and
protected input witness private. Ordinary Activate cannot confirm a picker or
Layer3 action. Dedicated protected confirmation requires its separately scoped
fresh owner-input route. None of the codec tests qualify that native boundary.
