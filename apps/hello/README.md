# Native Hello A/B source application

The `ev-native-hello` binary has separate `native-a` and `native-b` features.
Both retain the six ordinary M4 App roles, 336-byte startup, one thread and a
measured four-page 16KiB RW/NX stack. Neither image starts with a File endpoint.
The older M4 `services/desktop` image and renderers are unchanged.

Both versions request private data asynchronously through RootEvents and receive
one typed ND1 reply through their actual AppControl endpoint. A reads the initial
1001 or preserved 2026; rollback/reinstall must never reset it. B reads first,
sets 2026 only when needed, and waits for the real durable Value reply. Only then
does the app advertise Ready and render `Saved value` from the returned integer.
The contract is `ev.app.private-data@1`, major1/minor0/features0, with an explicit
`AppPrivateData` package request. Declaring that request grants no authority:
Root must bind actual current PID/TID/incarnation to its admitted active package
and private-data namespace, using one outstanding exchange and exact recipient.
The wire names no AppId, global operation, epoch, volume or sector.

The finite client accepts one Read and an optional different-value Set. A
successful Send means request acceptance, never durable completion. Full before
acceptance may retry the same bytes under the finite stop; an accepted request
is never retried. No repeated Read cycle or same-value Set can turn an old reply
into a new completion. Cross-incarnation stale replies must also be excluded by
the actual controller/endpoint lifecycle; a scalar codec cannot provide that.

Open File and Crash Me retain their M4 controls. On each new selected handle,
the App confirms exact SEND rights, reads a baseline counter/payload, attempts a
real Replace through that same READ endpoint, requires File `Denied`, and reads
again to verify the counter and payload are unchanged. It emits EVFLRO01 only
after all those actual exchanges, then the existing EVFILRD1 and Present. The
marker is diagnostic; the executor and cold observer must verify real route and
storage facts. Cancelling a replacement preserves/re-reads the current file.

Pixel writes use the [userspace graphics boundary](../../libs/userspace-graphics/src/lib.rs)
with a narrowly unsafe validated-mapping constructor. The app never manufactures
RAM ownership from an address or shared Rust reference. Raw startup/File-window
access and the deliberate contained Crash Me fault remain small documented
unsafe blocks; the safe view/data/contract helpers forbid unsafe code.

Source/host/target/linked-image checks do not prove an actual persistent lifecycle,
selected-file grant or update/rollback. Those require the source-matched Native
Root executor, real Store publication/reopen, authenticated events and actual VM
captures/diagnostics. The default M4 fixture remains a separate accepted scope.
