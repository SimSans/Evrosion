# Native Inspector

This separate M8 app renders resource and permission data sent by Root on its
independently installed sole-SEND control route. It has no ambient process lookup,
Job control, file authority or protected presentation role. Before a complete
valid snapshot, it displays no synthetic counters and submits no Present.

The strict336-byte V1 profile has six roles matching the App graph: own Surface
RW7, Present SEND8, RootEvents SEND8, RootControl RX|CONTROL272, Frame RW7 and
GrantInbox RX|CONTROL272. Limits are `[16384,128,1,1]`. Native SelfIdentity59/60
must match startup process/incarnation. Configure accepts only instance4 and a
nonzero mapping epoch; Ready4 is an ordinary actual-origin protocol event, not
permission or proof of an accepted frame. ScenePart low/high supplies the full
Root scene revision. All other apps reject this instance.

Root sends SDK Command12 InfoWord: byte3 is `field | (high<<7)`, bytes4..8 are
one u32 half. Required fields0..76 and120..125 must each arrive with both halves,
then127 commits the same exact nonce as field0. Field0 is a nonzero u32 nonce
encoded as u64 with high0; exhaustion/stale reuse refuses rather than wrapping.
Duplicate, missing, unknown or invalid words never replace the published data.
Each new field0 begins a private bounded staging snapshot. Partial observations
remain private while the last committed snapshot stays intact.

| Fields | Root observation |
| --- | --- |
|0|Exact snapshot view nonce|
|1..72|Six rows ×12 full u64 values|
|73,74|Page0/1 and total12 rows|
|75,76|Start/end sample ticks; an interval, never an atomic census|
|120..125|Layer1..3, scale1..4, contrast, thick focus, four2-bit file lease permissions, phase0..3|
|127|Commit, equal to full field0|

Row metrics are packed state/role; actual Process ID; actual Thread ID; Job ID;
CPU used/limit; Frames used/limit; Processes used/limit; Threads used/limit.
State0 means absent and requires all row words0;1 live,2 stopped,3 unobserved.
The role tag is Root0 or Child.index+1. Observations must come from actual
38/42/55 joins; zero/default data cannot stand in for an unobserved live row.
The app preserves all64 bits and renders selected CPU/frame values directly.
Permission values0/1/3 mean none/READ/READ+EDIT; they remain descriptive and do
not mint a File SEND. The unused App frame is never read and unsolicited actual
File grants are closed without constructing a File client.

Header.view_revision equals the exact committed snapshot nonce. Focus, selection
highlight and resize repaint preserve that nonce while the full64-bit frame
counter increases. Root can join Display's accepted view3 to its snapshot and
actual current model. The normal surface is320x180, bounded to320x200, with a
256-byte V5 header. Full64-bit Present requires matching reply/returned credit;
MAX is a completed refusal. Other errors fence the surface and stop interaction.
No protected Root surface/control mapping is available to this app.

Actions1..13 are refresh, next page, previous page, focus row, stop request,
restart request, revoke file request, cycle layer, contrast, focus style, scale,
shutdown request and restart-all request. Actions4..7 bind selected row0..5;
others canonically carry row0. SDK Event8 packs action/row in byte3 and the full
u32 view in bytes4..8. A row or PID in this data never supplies authority. Root
must match the current actual sender, forwarded physical gesture, accepted
snapshot/model and actual current ProcessCONTROL, then separately obtain any
required protected confirmation. An app event cannot approve an owner prompt.

Public `hit_test` maps actions1..10 to five columns at y0..39, actions11..14 to
four columns at y40..59, and row selection100..105 at y64+10×row. Root owns the
actual accepted-view/focus binding and tracks forwarded row selection before
matching an action gesture. These pure coordinates are not evidence of input.

Host tests cover exact full64-bit data, publication only after complete commit,
partial/duplicate/stale/refused preservation, intent correlation and clipped
pixels. Native link/ELF/stack receipts are local preflight; actual Root sampling,
39-origin input/event dispatch, permissions, recovery and VM acceptance remain
separate gates. The initial failed fixture incorrectly treated permission255
(all four leases RW) as invalid; the test now uses forbidden value2.


The current source adds action14 Assistive, which emits only an A1 attention
request. It cannot approve its own scope. Root's independent physical Controls
or Esc path presents the actual Inspector/owner identities and separate metadata,
action, document-text and protected-confirmation choices. App scope excludes
Root dialogs; Root scope explicitly includes current/future protected names and
metadata. Protected confirmation is a separate opt-in beyond ordinary actions.

The consumer stages complete16-node pages in process-private resident buffers.
Root relays only validated source snapshots bound to accepted full64-bit
model/view/frame/mapping tuples. The Inspector's header uses the complete page's
nonce; Receiving placeholders never acknowledge a new page. An actual accepted
Present emits a correlated marker; Root independently queries Display before
accepting it. The A1 toolbar occupies three20-pixel rows, with eighteen tools;
node rows begin at64. Prev/Next navigate nodes or the escaped private text view.
Bounded128-byte UTF8 reads use the exact ordered operation descriptor, a complete
immutable range result, and zero-tail validation. More text advances by actual
returned UTF8 bytes; no File2 window or another process's mapping is borrowed.

Ordinary Activate cannot approve protected Select/Confirm. Dedicated Confirm
only sends intent; Root requires the current scoped provider and a private ticket
from a fresh actual post-barrier physical gesture over the accepted visible
Inspector control. Revoke/new source cannot discard a partial operation or
snapshot stream: matching ordered abort/drain must finish first. All new code
is a component under qualification; retained old Inspector ELFs and earlier VM
results do not prove this consumer or its authority path.

Inspector also has a separate bounded self-description provider. It projects
its actual committed resource model or reader controls into at most sixteen
nodes per page. Stats uses four pages (overview, all fourteen tools, visible
resource rows/counters, visible settings); reader mode uses five (overview,
two tool pages, visible source-row controls, redacted private viewport status).
Root's original full64-bit model/view/frame/mapping tuple is preserved. Partial
external snapshots/operations/ranges and a pending own repaint are unavailable
for capture. The native adapter requires the exact own successful Present and
current scene; snapshot SEND uses a separate resident immutable outbox.

This Internal Inspector-local wire is deliberately separate from A1 consumer
traffic. Root requests `["IS",op,page,nonce:u32le]`, with op1 for page0..4 and
op2/page0 for an exact matching Abort. Replies use `"IT"` followed by the
canonical A1 field:u16le and word:u32le. Nonzero/non-MAX monotonically increasing
nonces, stream ordering and matching AbortAck use the SDK publisher. Actual
successful SEND advances exactly one held word; Busy retains it. A new request
cannot replace a busy outbox. The actual Root must authenticate the Inspector
sender, bracket its current accepted Display tuple, quarantine partial/stale
streams and keep this tree distinct from the selected external source.

Nested provider names, document bytes, range lengths and offsets are redacted
from this public self projection. A grant to Inspector's own metadata cannot
re-export protected Root filenames or copied document text. Existing underlying
READ/TEXT scopes remain necessary. Enabled bits reflect the real local model
and scope bits. Dedicated Confirm is marked protected and advertises zero
ordinary actions, even when the separately authorized physical route exists.

The executable accepts a Root-forwarded focused `?` to enter/leave local control
navigation, arrows to traverse visible enabled controls and Enter to request the
selected ordinary control. It draws an actual focus outline and control caption,
then uses ordinary Present; every requested effect still passes Root policy.
Dedicated protected Confirm is excluded from this route. Root retains Esc and
global Tab attention. The separate Root native receiver authenticates the actual
Inspector sender, brackets the accepted Display frame, and forwards local input
only after a complete current own tree. Its immutable partial stream and exact
AbortAck remain separate from external provider data and consent.

Automatic resource samples coalesce into one desired repaint. After an actual
successful Present, another automatic repaint waits2048 ticks; incoming complete
samples replace only private Model data and do not renew that due time. One
explicit refresh applies to its next complete sample. Local controls and scene
changes may request an urgent repaint, but never bypass an exact in-flight
header. The existing1024-tick Present cut is unchanged. Any unknown or mismatched
completion retains the original header and permanently fences presentation.
No healthy joined VM, complete accessibility, scaling or M8 gate claim follows
from component checks alone.
