# Interface definitions

Typed, versioned component contracts and generated bindings.
Follow [E-015](../architecture/plans/core/E-015-system-api-and-abi.txt) and
[IPC discipline](../architecture/designs/IPC_DISCIPLINE.md).

The first closed bootstrap subset is [ev.test.echo@1](ev.test.echo.v1.json), with
generated no_std Rust bindings in
[echo.rs](../libs/userspace-contract/src/echo.rs). Run
`python3 tools/idl/generate.py` after an intentional schema/generator change, or
`python3 tools/idl/generate.py --check` to reject stale generated bindings. This
small generator accepts only its explicit subset; unsupported declarations fail
instead of losing semantics. It is not a general-purpose IDL language or Stable
platform contract.

Generator negative cases are in `tools/idl/test_generate.py`; run
`python3 -m unittest discover -s tools/idl -p 'test_*.py' -v`. Generated Rust tests
run with the `ev-userspace-contract` host tests after its module is wired in.

The eight-byte wire record is `EV`, version 1, request opcode 1 or response opcode
2, then one little-endian `u32` value. Echo returns the same value. Unknown magic,
version/opcode, wrong lengths or any transferred capability fail validation. All
`u32` bit patterns are valid payloads. Generated request/response types prevent
direction confusion, and the server stub validates before invoking the handler.

The asynchronous transport permits at most four messages per
endpoint, eight bytes and zero transferred capabilities per message, with one
outstanding request per client. The kernel transport must require a finite
absolute monotonic deadline and expose full queues as `WOULD_BLOCK`; decoding
does not itself enforce clock, capability ownership, queue or wait semantics.
The same schema declares a bounded non-reentrant synchronous method. Generated
`client_call` accepts a transport and absolute deadline; the userspace runtime
connects it to kernel-protected calls and scheduler waits. Timeout ends the wait
while late execution remains tracked until acknowledgement or verified death.
Actual Root/Echo boot proofs include expiry, discarded late responses and stale
completion rejection. Bounded M2 acceptance
also records capability-bearing RPC and AF-IPC-001–010 coverage. This bootstrap
generator remains a deliberately small subset; broader public IDL/contract and
compatibility coverage must not be inferred from that proof.

M8 adds separate Internal [workspace@1](ev.internal.workspace.v1.json) and
[File@2](ev.internal.file.v2.json) controls. They preserve File@1 bytes, describe
dynamic generation-bearing objects and namespace operations, and carry bounded
larger-file staging/chunk metadata over separately owned MemoryObject loans.
Actual receive routes and authenticated callers supply authority; wire IDs and
names do not. [ADR-0105](../architecture/adr/ADR-0105-versioned-workspace-and-large-file-contracts.md)
defines exact revision/hash confirmation, uncertainty, scoped operation/transfer
IDs, canonical encoding and actual adapter obligations. These generated host
codecs do not establish actual RPC/grant/storage/VM acceptance or a Stable SDK.
