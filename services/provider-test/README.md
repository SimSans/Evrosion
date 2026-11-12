# Internal provider replacement actors

`ev-provider-test` has separately measured `consumer`, `provider-a` and
`provider-b` executable features. These actors use the active generated
`ev_userspace_contract::provider` interface from
[`ev.test.provider@1`](../../idl/ev.test.provider.v1.json). This is a closed
Internal test contract, not a Stable extension API, installed provider registry
or proof of an actual running swap.

The eight-byte cap-free request computes checked `2*x+1` for a bounded u32 input.
A uses arithmetic; B uses a fixed 31-step bit construction. Malformed/range input
refuses before the generated handler. The typed client validates response shape,
refusal code and attachment count and preserves finite absolute deadlines and
actual transport errors. Neither wire values nor an endpoint wrapper mint
capabilities, select a provider or identify a kernel process.

The source [Root policy](../root-supervisor/src/provider.rs), selected only by the
separate `provider-switch` feature, receives ordinary 336-byte startup with six
explicit grants. Root creates Jobs and request/event/consumer-control endpoints,
authenticates actual event origins, stops/reaps A after actual completed calls,
admits B, and binds the same logical request Endpoint. Root resumes the same
Consumer only through its private control endpoint. The Consumer constructs one
generated client and keeps the same installed SEND handle across both phases;
it has no provider identity or implementation-selection input.

The shared declarations in `src/lib.rs` are the source of startup role/limit
checks: Root `[Memory READ, Endpoint SEND, Job CONTROL, Memory READ, Memory READ, Memory READ]`, Consumer
`[Endpoint SEND, Endpoint SEND, Endpoint RECEIVE|CONTROL]`, providers `[Endpoint RECEIVE|CONTROL, Endpoint SEND]`. Root
limits are `[16384,64,4,8]`; children use `[16384,32,1,1]`. Every executable declares
its own four-page 16KiB RW/NX stack at image pages 256–259, with guard holes 255/260.
Ordinary bootstrap/page 511 stack metadata and the six/eight-role v1 ABI are not
replaced. The controller-provided finite stop is not authority; client requests
use checked stop+512, and the provider verifies actual protected deadline 29.

Generic kernel lifecycle/RPC/physical-owner integration and a source-matched
actual VM are required before provider replacement can be accepted under
E-025.64. Kernel code must not choose A/B, compute replies, reset tables or patch
the consumer's handle. Pending execution prevents stop/rebind; accepted timeout
is not evidence of nonexecution. A stopped receiver can be reopened only with
actual CONTROL and exact new RX authority, preserving the same endpoint, escrow
and monotonic queue clock. Actual origin IDs are diagnostics; retained process
and endpoint capabilities authorize every owner action.

A completed live switch is narrower than E-024's durable provider binding
configuration. Persisted owner preference, reboot recovery, compatibility
rollback/quarantine and a provider catalog remain separately scoped integration;
no package advertisement or Ready message can self-promote into authority.
