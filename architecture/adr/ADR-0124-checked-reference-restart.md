# ADR-0124 — Checked reference restart

Status: Accepted Internal Level B mechanism; prototype and actual reset qualification in progress. No Main adoption.
Date: 2026-11-16
Related: ADR-0121; M8-08/10/12/13; INV-AUTH-001/002/005, INV-IPC-005, INV-LIFE-002/005.

## Problem and alternatives

M8 requires graphical checked restart as well as shutdown. The selected
shutdown path already captures actual Root/device controls, drains accepted
work, stops actors and performs trusted Root ATA FLUSH and NIC STOP/scrub.
Its generic Root EXIT remains a failure. A host QMP reset, a new host process,
or a restart label supplies none of the guest retirement proof.

Reuse that exact fence and add a selected platform reset after its checked
completion. Reconstructing a live graph inside the old Kernel would require
an additional object/device lifetime proof; it is not this reference restart.
Granting a reset I/O port to an App or ordinary Shell would widen authority
without solving storage or device retirement and is rejected.

## Additive negotiation and captured intent

INFO66(0,0,0,0) retains the exact existing shutdown-only scalar response.
INFO66(1,0,0,0) is a distinct restart-support query; every other operand is
reserved. The selected Q35 test executor alone advertises the additional bit.
Old Roots continue to query0. A new Root receives Unsupported from an old
Kernel for query1 and refuses restart before stopping any application.
All tagged replies, including malformed requests, still clear capability and
fourth-operand outputs.

CONTROL67 BEGIN0 retains its old meaning. BEGIN_RESTART1 captures Restart in
the same one-use latch and uses the same exact actual Block/NIC pair, token1
and original finite cut. Neither a second BEGIN nor COMPLETE2 can select a new
intent, pair or deadline. The existing actual running Root/custodian proof,
non-device exits, RPC/window/mailbox/selected-debt checks, sticky partial
failure and trusted Root physical device work are unchanged.

The executor stops after completed Shutdown or Restart without resuming Root.
Its proof distinguishes them: Restart cannot emit clean_shutdown=true or take
the debug shutdown exit. A checked_restart record means the captured exclusion
and trusted device proof completed before the original tick cut. It does not
prove that the later platform reset occurs before a wall-clock deadline: PIT
has stopped and bounded terminal reporting precedes reset.

## Selected platform action

The sealed Internal Q35 executor emits one port write, OUT8(0xCF9,0x0F), only
after its completed Restart proof. The upstream reference model defines that
[ICH9 port](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/include/hw/southbridge/ich9.h),
uses that value in the [Q35 FADT reset descriptor](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/i386/acpi-build.c),
and requests a guest reset in the [ICH9 handler](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/hw/isa/lpc_ich9.c).
Those sources guide the adapter; they are not attestation of the installed
binary or physical hardware. No ordinary capability exposes this port.

If reset does not occur, CLI/HLT retains the quiesced machine. It cannot resume
normal work or manufacture success. A finite host observation must classify
that fallback as failure. Physical-machine and general Kernel replacement
qualification remain outside the selected reference scope.

## Required actual evidence and preservation

Keep ordinary profiles' -no-reboot protection. Only an explicit restart
profile may permit guest reset. It must correlate the captured checked_restart
and request records with an actual guest RESET event, then a fresh second boot
of the exact selected Kernel/bundle on the same owned disk. Reopen the saved
object through native File clients and verify its identity, revision and exact
bytes; subsequently perform checked shutdown and independent cold inspection.
No first marker, reset request, exit code, unchanged screenshot, or host reset
alone qualifies restart. Synthetic input is not human approval.

Tests must cover old query0/Root behavior, malformed query1, unsupported restart,
full controls/token, early/expired completion, busy debt and mode-switch
refusal, unchanged Root retirement order for both intents, and failure to
observe the second boot. Keep all failed attempts, immutable source/artifact
pins and original data. Use one shared compiler cache and source-only snapshots.

This extends only ADR-0121's shutdown-only selected-platform boundary. Its
authority, original cuts, physical proof attribution, diagnostics limits and
all existing data/capability guarantees remain unchanged.


## Optional fresh-input pacing observation

The first owned two-boot trial reset and reopened the exact saved text, then timed out at final shutdown. A new Input lifetime starts without prior Enter-break knowledge. A first make cannot approve merely because the key is currently not held; its later break establishes knowledge only for a later make. The title and Confirm caption also precede the post-Present Input barrier and attestation, so visible pixels alone do not establish arming.

Selected Root may optionally issue INFO66 query2 with nonce, accepted frame and a packed actual barrier snapshot only after successful InputBarrier and attest_presented. Bits0..31 carry the barrier sequence,32/33 Enter-held state,34..36 pointer-held state,37..39 pointer-release knowledge,40 restart intent,41/42 main/keypad prior-break knowledge; higher bits are zero. Nonce/frame zero orMAX and sequenceMAX refuse. Existing queries0/1 and power controls retain their previous bytes and behavior. The tagged reply always clears capability and serial fields.

The selected Kernel validates actual captured Running Root context, accepts at most8 diagnostic reports per boot and refuses reports once power is active. It emits current build, actual Root process/thread and the opaque metadata with scope=trusted_root_pacing_only. This has no authorization, consent, device or power effect. Root ignores a missing/denied optional diagnostic while retaining the same witness; older/default Kernels still refuse the new query.

The two-boot observer records first postboot shutdown arming and its real release knowledge, cancels that dialog, delivers an actual main Enter break outside any protected dialog, then requests a new dialog. It requires a different nonce in the current boot, a completed post-attest record, prior main-break knowledge and neither Enter held before sending its one released confirmation. The original300-second host deadline and original guest power cuts remain unchanged. No protected confirmation is queued or retried, and no Input freshness rule is weakened. Reports pace reference-device test input; actual guest reset, fresh same-build boot, native reopen, final checked shutdown and cold bytes remain separate requirements.
