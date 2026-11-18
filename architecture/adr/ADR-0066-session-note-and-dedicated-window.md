# ADR-0066 — Session notes and a dedicated note window

Status: Accepted mechanism; joined runtime acceptance incomplete

Date: 2026-11-12

Decision level: B

## Context

A useful developer session needs editable work that survives App and Shell
restart and a cold VM reopen. A displayed Save acknowledgement must represent
an actual committed operation. Reusing the File window for a second protocol
also lets an uncooperative App overlap Note SEND and File RPC operations on the
same physical page, even when the bundled client serializes them correctly.

## Decision

Keep the App's editing model separate from its storage client. Typed bytes
remain private App state. Loading, unsaved changes, saving, saved and unavailable
are explicit states. Changes made while a Save is pending remain unsaved after
that earlier Save completes. Printable ASCII and a128-byte note are the bounded
initial editor contract; broader text support remains product work.

Use the generated versioned session-note scalar protocol to identify one
nonwrapping request nonce and operation. Endpoint provenance supplies the actual
App process/thread; the request cannot nominate an AppId, capability, volume or
sector. Root verifies the current package's explicit note contract and private
data entitlement before touching storage. A matching scalar acknowledgement
alone is insufficient: the client validates the returned envelope and exact
proposal before releasing its window loan or showing Saved. Unknown, late or
malformed completion quarantines the loan; it does not authorize reuse.

Root owns a distinct note Store extent at physical sectors112..125. Existing
AppData schema1 and File extents retain their meaning. Note schema2 uses a
checked256-byte envelope with stable AppId, counter, length, bounded text and
checksum. The checksum detects corruption; it is not a release signature.
Creation requires the entire extent to be blank and an admitted current App.
Writes compare the actual freshly read counter, execute once, and read back the
committed bytes before returning Written. Uncertain mutation is fenced for
recovery, never automatically replayed. Original Store creation identity remains
historical context across later Root images rather than being rewritten to
match whichever image is running now.

The final V4 graph allocates a physically distinct Note MemoryObject: Root
source28 maps at506, and the App's seventh role maps at507. The existing File
window remains App508. Another derived handle to the File object does not count
as a distinct object. SDK/Core admission rejects this alias atomically. Actual
hardware mapping uses the existing MappingLease owner, exact physical backing
checks, RW/NX policy and inactive-root teardown; a new metadata role is not
itself proof of those obligations. Root retains its claim while an App exits or
faults, and retirement waits for genuine old-incarnation quiescence. A failed
acknowledgement debt cannot silently release that memory.

An intermediate Native3 integration prototype maps Note through the existing
File object and relies on the bundled client's serialization. It is useful for
isolating editor/storage integration, and is explicitly excluded from final
hostile-client memory isolation acceptance. Final V4 admission and actual
separate backing are mandatory before M6 acceptance.

## Validation and remaining work

Focused tests exercise real Store format/read/execute/readback, stale and wrong
identity requests, preservation of schema1 data, malformed envelopes, client
quarantine, actual role alias rejection, editor state and full scanout references.
The scripted guest driver uses genuine Input/Shell events and matched Kernel
observations, then independently decodes retained disk bytes. It compares the
original seed to the creation baseline, every byte outside the three explicit
creation extents, subsequent changes outside the note extent and a read-only
cold reopen. Synthetic parser/reference tests are not guest execution evidence.

Actual joined VM typing, durable Save, read-only picker refusal, crash/relaunch,
Shell restoration, cold persistence and V4 hardware ownership remain required.
No prototype or library result alone closes M6-02 or the authenticated update
and offline recovery gates.
