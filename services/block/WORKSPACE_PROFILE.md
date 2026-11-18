# Additive workspace Block profile5

Status: host tests and actual linked single-driver checks pass; V5 admission,
device execution, provisioning and recovery VM evidence pending. See
[workspace storage](../../architecture/designs/WORKSPACE_STORAGE.md).

`workspace-storage` exposes a non-executable `workspace::Region<T,W>` SectorIo
adapter using existing `store_io::Wire`/`Window`. Construct the actual transport
with `DesktopEndpoint::for_session_transactions` and one independently owned
window. It preserves the original aggregate deadline, clips each child sector
call to at most1024 ticks, retries no accepted uncertainty, and poisons window
access after a transport/malformed/wrong completion. Metadata alone proves no
lease, port grant, peer stop or timeout-safe buffer reuse.

`workspace-driver` is an explicit new actor, preserving the old codec and driver
profiles. The exact device is196608 sectors/96MiB,512 bytes per sector, serial
`EVROSION-M8-WORK` padded with four spaces. Legacy `AtaPio::new` and its parser
still require the original8192-sector `EVROSION-M3-PIO` identity. The new
constructor uses a const profile, including reset/re-identification through
SessionDisk; no runtime packet can switch device policy.

| Actual receive route | Logical sectors | Physical sectors |
|---|---|---|
| Root System | Existing profile4 mappings only | Original ranges within0..8191 |
| Legacy File |0..13 and16..29 |32..45 and48..61 |
| Workspace |0..152321 |16384..168705 |

The original prefix0..8191 and guard gap8192..16383 are inaccessible through
the Workspace route. Root/File routes cannot name the workspace. Unknown routes,
malformed requests and bounds refuse before window or ATA effects. Replies
retain original logical sectors; global ATA flush may persist prior writes of
another client, with no cross-region atomicity claim.

The strict ordinary bootstrap has eight roles:1ports3;2SystemMemory7/page508;
3SystemEndpoint272;4legacyFileMemory7/page507;5legacyFileEndpoint272;
6RootEventsSEND8;7WorkspaceMemory7/page506;8WorkspaceEndpoint272. All three
receive routes self-bind before generic Ready. Original roles1–6 retain their
meaning. V5 Root/Kernel must prove distinct actual Memory/Endpoint identities,
mapping leases, actual owners and the measured8-role manifest. Integer handles
and startup parsing cannot supply those proofs. Initial declared limits remain
[16384 CPU ticks,32 frames,1 process,1 thread]; linked12 image/stack pages do not
by themselves certify complete frame admission.

Retain the ORIGINAL4MiB disk unchanged. A separately owned96MiB test image may
receive a byte-identical verified copy of that prefix, then guest-only new
workspace provisioning in its isolated extent. This is an explicit container
transition on a copy, not a claim that the original old Kernel/driver accepts
the new96MiB geometry. Never truncate/resize the original disk or remap its
Store-v2/File-v1 IDs. Host sparse-file preparation supplies no guest format or
durability evidence; actual guest Block/SectorIo execution must establish it.

`qualify_workspace.py` builds only this driver with the established userspace
large-code-model flags. It retains unstripped debug ELF, strips debug with the
pinned llvm-objcopy, compares every loaded segment/entry identity, keeps the
existing1MiB executable container bound and runs the established16KiB stack
census. The first direct kernel-code-model link failure remains retained rather
than relabeled as target success. Read [the scoped qualification record](WORKSPACE_QUALIFICATION.json).
