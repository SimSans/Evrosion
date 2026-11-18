# ADR-0080 — Retain actual storage ownership across bounded content steps

Status: accepted implementation refinement, Level B, 2026-11-12.

## Problem

Root owns one serialized Block window. A borrowed content Arena/Stage correctly
excludes other writers, but retaining its borrow inside the same Controller as
Native State would self-reference that State. Running the entire multi-megabyte
blank scan or transfer in one call would prevent normal Root UI/event handling.
Returning cached cursors and rebuilding a backend between ticks would discard
the actual accepted-operation fence and weaken the ownership boundary.

## Decision

Keep the borrowed content API and add owned Stage, Reader and Verified forms.
Each retains the same Arena and actual Backend by value, with the original
transfer horizon, sequential hash state, durable append high-water and poison.
They reuse the borrowed operation bodies. A consuming failure returns that
same Arena; it does not manufacture a fresh ready owner. Completed bounded
steps can return to the Controller event loop. Provisioner already owns its
Backend and scans at most eight sectors per step.

Native-network State uses a private BackendSlot. Taking its content backend
moves the actual window/transport into an opaque OwnedBackend. While absent,
State exposes cached UI values, reports busy, and refuses storage/data/note
operations before I/O or nonce/credit consumption. Inspection reports not
collected. The empty device view also refuses every read, write and flush;
there is no unchecked unwrap or replacement backend.

Restoration accepts only the same private backend identity and nondecreasing
mutation count. A rejected foreign return retains its owner for its caller.
Actual transport poison survives restoration and continues to require recovery.
The identity is allocated once by a checked private atomic counter; exhaustion
refuses construction. It is neither persisted nor a wire capability, freshness
witness or cross-boot identifier. Ordinary profiles retain the previous direct
Backend type.

Metadata transactions retain their explicit at-most8192 horizon under one
original transfer cut; each actual Block RPC independently captures at-most1024
before window publication. Payload/readback/scan steps keep their at-most1024
cut. Ownership movement renews none of these bounds. Abandoning a reservation
never reclaims or overwrites its durable extent. No GC, automatic reformat,
release-trust, health or KnownGood claim follows from these storage forms.

## Evidence and remaining work

Content tests stream/hash/read back256KiB through move-only continuations,
exercise a retained failed reservation and cold reopen, and retain the earlier
222 interrupted/torn cold scenarios. Actual Root Backend/Block route tests
exercise owned provision/stage/readback/publication/restoration and protect all
old disk regions. Active App busy tests refuse data and note access without
consuming the actual wire failure sentinel or note nonce, then resume after
restoration. Foreign-return and poisoned-return tests preserve both owners.
Host and bare-target strict checks pass for the owned library and Root.

Controller scheduling, explicit Stage/Activate UI, real guest transfer and
integrated trusted metadata publication remain separate required proofs.
These APIs support that integration; they are not a guest or M6 acceptance.
