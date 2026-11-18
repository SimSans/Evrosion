# Offline native document session

This bounded development reference edits the selected **Notes.txt** or
**Private.txt** File object. Each document supports at most 224 UTF-8 bytes.
It runs offline in the owned QEMU reference. Human usability acceptance is
pending owner feedback.

Follow the [Linux build/run guide](QUICKSTART.md) to prepare the toolchain and
dependencies. Use a terminal in the graphical Linux desktop session and run
from the repository root:

```bash
cargo ev document-session
```

Keep the launching terminal open. The first launch builds and retains an
optimized guest cohort and copies the fixed reference seed into a new owned
disk. Later launches reuse those exact guest artifacts and the same disk.
They do not rebuild or bind saved data to a new catalogue. Missing, incomplete
or modified retained state is refused and preserved; there is no automatic
reset or migration.

The session state lives under this checkout's
`build/m7/document-session/`: `data.raw`, its ownership/lock files and the
complete `boot-set`. Keep that directory together. Existing 0.2 session disks
under `build/m6/session` and `build/m6/network-session` remain separate.
Each launch prints its evidence folder. Raw before/after snapshots in that
folder contain document data; the manual guest does not dump full document
text or semantic snapshots into its serial log.

## Open, edit and save

1. Wait for **Home**. Press **Enter** to launch the application. The first
   view says **No document** and focuses **Open document**.
2. Press **Enter** to request editing. Read the trusted picker's edit intent.
   **Notes.txt** is initially selected; **Tab**, **Up** or **Down** changes the
   selected File. Press **Enter** to approve that exact object, or **Escape**
   to cancel. Read-only approval cannot authorize saving.
3. The selected document opens with the text focused and the cursor at its
   end. To replace its contents, press **Tab** to focus **Select all**, then
   **Enter**. Type a short test string such as `Guide_03`.
4. Read the visible **Unsaved changes** state. From text, press **Tab** to
   focus **Select all**, then **Tab** again to focus **Save**. Press **Enter**.
   Wait for **Saved**. The application reports Saved only after matching
   durable commit acknowledgement and readback of the same revision/content.
5. From Save, press **Tab** to focus **Close document**, then **Enter**. The view returns
   to **No document**. Press **Enter**, then approve the same File again in the
   trusted picker. Verify the saved text before editing anything further.
6. Type `finish` and press **Enter** in the launching terminal. Wait for checked
   shutdown and the command to finish. Run the same launch command again,
   reopen the same File and verify its saved contents before writing.

Pointer clicks can focus or activate the same named controls. Clicking the
document text moves its cursor; a click grants no File authority. **Left** and
**Right** move by UTF-8 scalar, **Up** and **Down** move within the displayed
text layout, **Backspace** deletes the selection or preceding scalar, and
**Enter** in text inserts a newline. Input uses the supported reference PS/2
keyboard map; printable ASCII is the qualified typing path. UTF-8 documents
remain byte-preserving when valid, while unavailable font glyphs appear as
`?`. This reference has no IME or screen-reader provider. Unsupported document
text is reported without rewriting its original bytes.

## Cancellation and uncertain saves

**Open read only** requests a separate READ grant. Save is disabled and text
input cannot change that File. A closed document has no retained edit grant;
opening again requires fresh picker approval.

Closing or opening another document with unsaved edits presents **Keep
editing** and **Discard changes**. Keep returns to the unchanged edit. Discard
abandons the unsaved changes without saving them. Cancelling a new picker
preserves the previously confirmed view.

Read refusal and error text before continuing. **Save unconfirmed** or storage
unavailability does not mean Saved. An accepted operation with uncertain
completion retains its exact proposal and cannot be silently retried with a
new counter. End the session, preserve its evidence and use explicit recovery
or reselection guidance for that state. Closing the GTK window interrupts the
VM and is recorded as an interruption; `finish` requests checked shutdown.

## Separate engineering exercise

```bash
cargo ev test document-session-guide
```

This explicit command runs the open/edit/save/close/reopen/cold sequence in GTK
using the same retained manual guest, with a **new test disk**. It records real
QMP keyboard events, original scanout PPMs, actual protected presentation hashes,
raw before/after disks and independent read-only File checks. It checks that the
retained manual disk stays unchanged. Normal `document-session` sends no input.
The engineering exercise and its screenshots do not establish human acceptance.

For owner feedback, record what you tried, whether Save and cold reopening
worked, and any unclear labels, focus changes, errors or delays. Human feedback
remains pending until it is actually supplied.
