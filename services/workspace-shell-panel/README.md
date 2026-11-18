# Native Shell panel

`ev-workspace-shell-panel` is the separate replaceable ordinary M8 Shell image.
It renders four launcher/window buttons and emits ordinary requests. It neither
draws the protected Root plane nor approves prompts, grants focus or claims that
a window is running from a label alone. Root owns those actual states and policy.

The strict336-byte V1 profile has exactly Surface RW7, Present SEND8, RootControl
RX|CONTROL272 and RootEvents SEND8, in that order, with UI limits
`[16384,128,1,1]`. Counts, roles, aliases and limits refuse before use. Native
SelfIdentity59/60 must match startup process and registered incarnation.

SDK Command Configure0 selects the Shell-only instance and nonzero mapping
epoch: `[W,1,1,0,epochLE32]`. It returns Event Ready0 `[E,5,1,0,0,0,0,0]`.
Every ordinary App locally rejects instance0. Ordered ScenePart low/high supplies
the complete64-bit Root model revision. The default Header is ProducerShell,
instance0, actual process/thread/incarnation, logical source Role::ShellSurface,
generation equal to full process ID, and640x18 geometry. Root registers it at
desktop y462; placement is Root's authority, never the Shell's claimed header.

Root may send Activate1..4 after configuration and scene readiness without moving
keyboard focus away from an App. Event Window1..4 is `[E,5,9,instance,0,0,0,0]`,
requesting Files, Editor1, Editor2 or Inspector. Root must authenticate the event
through actual RECEIVE_EVENT39, join both sender Process and Thread to its live
Shell, validate the current forwarded gesture/model and inhibit requests while
protected UI is pending. No event itself authorizes an action. Ordinary Shell
cannot return owner confirmation or access Display's Root-only registration area.

The app writes only bounded private Surface pages384..446, with the V5 header
at0..256. Full64-bit Present must return exact frame correlation and actual
credit; MAX is a completed refusal. Unknown replies fence the retained surface
and stop new requests/pixels. Quiescent Close closes only the local Present SEND
before reporting Closed/exit; Root still owns actual retirement and backing.
There is no file, namespace, Job-control, raw input or device capability.

Public `hit_test` divides the panel into four equal logical button areas; Root
owns actual focus and hit routing. Host profile/pixel/intent tests and native
ELF/stack preflight do not prove actual grants, accepted composition, replacement,
gesture delivery or VM qualification. No legacy Shell feature, protocol or
physical/consumer deployment qualification is implied.
