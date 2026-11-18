# ADR-0123 — Authenticated File2.1 admission and versioned selection

Status: Accepted Internal Level B refinement; fresh coherent runtime qualification pending.
Date: 2026-11-16
Related: ADR-0111/0113/0118/0119/0121/0122; INV-AUTH-001/002/004,
INV-IPC-004/005, INV-LIFE-001/002, INV-EVO-006.

## Problem and retained constraints

The new Editor uses bounded staged Verify before Commit, but its package still
declared File2 minor0/features0. An old Workspace could therefore satisfy the
declared package requirements, receive a writable binding and reject Verify
only after staging. The existing client correctly fenced that failure, but
availability had not been established before writable handoff.

Source constants, an ELF resource shape, a service Ready packet and descriptive
selection bytes cannot establish that a particular live service implements a
new feature. Existing Root control/window ownership, actual sender provenance,
package identity, File rights and accepted-operation uncertainty remain separate.
No endpoint, bank, Kernel authority, frame envelope or bootstrap ABI is added.

## Loaded support and package admission

File2 retains major2 and all old wire records/opcodes. Its additive compatibility
metadata is minor1 with `STAGED_VERIFY` bit0. Old minor0 clients retain methods
1..6, the original Bind/Selection1 flow and the historical Commit verification
path. The original File1 codec, disk format and readonly bridge remain unchanged.

Root first checks the actual readonly package banks for integrity, exact
catalogue binding, platform, ABI and schema. This preboot structural check
explicitly defers contract availability. After the actual Workspace Ready and
before delegating or starting Apps, Root probes the existing dedicated
RootWorkspaceControl endpoint using its sole window at503..504 and one original
finite cut. The native Workspace receives only on its already protected role16,
captures real ServingOrigin, and validates the live Root incarnation and pinned
process/thread/registered token/endpoint/RPC epoch before inspecting the frame.
Packet fields cannot establish this authority.

RootControl opcode8 is `FileContract { token }`. Token is correlation only.
The distinct256-byte `EVWFCA01` reply carries exact request16/token32, status8,
and, only for Applied, majoru16@40, minoru16@42 and featuresu64@48. Every other
byte is zero. The operation performs no Dataset/Store I/O or binding. Normal
scoped request/fingerprint replay and terminal-seal refusal still apply.

Native Root retains the reply with its captured Workspace ProcessCONTROL,
process/thread/incarnation, control endpoint, boot/mapping epoch and measured
image/descriptor. Actual identity and Observe checks bracket the probe and
every later use. A changed, stopped, replaced or fenced service invalidates the
cached support. No automatic renegotiation or legacy-server fallback follows
uncertain acceptance. Root's one transport now retains the exact endpoint,
request, original cut and frame across failure; a new client or packet cannot
reset that journal/window fence.

Only this observed support fills Root's File entry in `LoadedContracts`.
There is no static runtime File support table. All package requirements are
checked after the probe and before App delegation. The producer now declares
minor1/bit0 for the actual new Editor implementation, whose explicit Selection2
validation was added separately. Producer declarations do not replace native
negotiation. Missing, minor0 or missing-bit support refuses the new requirements.

## Binding and selection

For a package with nonzero File minor/features, Root rechecks its immutable
package requirements against the current actual service and requests protected
`BindContract` opcode9. It carries the old exact Bind fields plus major2@104,
minimum minor@106, required bits@112 and Selection version2@120. Workspace checks
support before route generation, storage access, window clearing or selection
publication. Unsupported requirements cannot install a binding.

The distinct `EVWFBA01` reply carries the same correlation/status/support fields
as the probe and Selection version2@56 on Applied only. A generic old Applied
response cannot qualify. Root requires the exact cached support, retains any
unknown accepted binding, and rechecks actual service identity immediately
before Kernel44 SEND handoff. Existing object/revision/name/namespace checks,
protected owner effect, actual old-lease retirement and real Kernel handoff
remain mandatory. No feature bit grants edit rights.

Selection2 retains the256-byte metadata record and receiver/nonce checks with
distinct `EVF2SEL2` magic. The previously reserved tail carries majoru16@216,
minoru16@218 and featuresu64@224; all other reserved bytes remain zero. The actual
new Editor explicitly dispatches by magic and requires major2/minor1/bit0 before
constructing its native File client. It retains support with that route and
rechecks it before Save/KeepDocument. Malformed Selection2 never falls back.

Old Selection1 remains byte exact for old clients. The new Editor accepts that
format only for the closed original File1 readonly projection: original volume
`EVRO-USERS-VOL01`, slot1/2, generation1 and ReadOnly. This descriptive exception
cannot enable edits. The service's actual route continues to enforce readonly
and original-media policy independently of every metadata field.

## Qualification and limits

Host checks cover absent/old/missing-feature support, exact probe and binding
correlation, canonical reserved bytes/directions, identity/control/endpoint/
epoch/image changes, and both old and new selection formats. The actual Dataset
test proves unsupported BindContract leaves I/O counters and route generations
unchanged, while successful Selection2 never widens a ReadOnly binding. Existing
one-MiB save, Verify, uncertainty, retirement, Quiesce and original-media tests
remain required.

Fresh strict host/bare checks and source-pinned Root/Workspace ELF and guarded
stack preflights are component evidence. A new coherent Root/Workspace/Editor
package VM must still qualify actual negotiation, writable handoff, Save,
cancellation, retirement and shutdown. This refinement alone claims no native
SDK/cancellation acceptance, installation, dynamic update, private-data handler,
clean physical shutdown or complete M8 acceptance. All existing bank, role,
mapping, CPU/frame and original-media limits remain unchanged.

## Alternatives

Raising a static Root support constant would advertise an unqueried service.
Post-staging Verify refusal would preserve uncertainty but leave admission late.
Reusing Selection1 reserved bytes would break its strict decoder. Automatically
falling back or issuing fresh requests after uncertainty would discard the
accepted operation's original ownership/cut. Expanding banks or authority does
not solve this compatibility boundary.
