# Local 0.2 walkthrough and owner feedback

This guide covers the bounded 0.2 network demonstration. Historical readiness
and stabilization results retain their original source identity and limits in
the local engineering archive. Changed source requires its own qualification.

Follow the [Linux build/run guide](QUICKSTART.md) to prepare the toolchain and
dependencies. Then run from the repository root in a graphical Linux desktop
terminal:

```bash
cargo ev network
```

Keep that terminal open. The command owns a developer volume under the selected
checkout's `build/m6/network-session`, preserves an existing compatible volume
and refuses incompatible retained state. It uses the QEMU reference profile;
it is not an installer or physical-machine qualification.

## Try the ordinary workflow

1. Wait for Home. Press Enter to open Hello. A reused compatible volume may
   contain a saved note; preserve or edit it using Backspace.
2. Type a short supported note, such as `check02`, in the focused note field.
   This is the bounded demonstration editor, not a general text application.
3. Press Tab to focus Save and Enter to request saving. Read the visible result;
   a request alone is not a successful save. Up returns focus to the note.
4. Escape returns to the launcher. From Home, Tab opens Connection and updates;
   use Back to return. Observe whether focus, status and errors are understandable.
5. In the launching terminal, `inspect` requests bounded resource/System reports.
   Enter `finish` there for checked shutdown and wait for the command to finish.
6. Run the same command again, open Hello and confirm the saved note appears
   before editing or saving anything in that new session. End with `finish`.

The public-only manual environment may show **Updates unavailable** because it
has no matching private development signer. Local editing/saving remains usable.
The separate signed update/failure/offline-recovery tests exercise the existing
independently provisioned development authority; this walkthrough neither copies
a key nor turns a development build into an official release.

## Feedback to record

Report what you tried, whether save/reopen worked, and which controls, focus
changes, labels, errors or delays were confusing. An ordinary text description
is enough. Owner feedback and acceptance are separate from programmatic QMP
tests and screenshots. Until the owner supplies it, the record must say pending.

The 0.3 proposal in the [stabilization plan](../../architecture/M6_STABILIZATION_PLAN.md)
uses that feedback to choose one useful native document workflow while keeping
accessibility, exact grants, offline use, data preservation and recovery explicit.
