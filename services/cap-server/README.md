# Capability Echo server proof actor

A separate source-built Rust/no_std process using generated
[cap_echo@1](../../idl/ev.test.cap_echo.v1.json) and the
[shared capability transport](../../libs/userspace-runtime/src/cap_echo.rs).
It receives exactly selector3 request RECEIVE|CONTROL and selector4 responseSEND,
with512 CPU ticks,16 frames,1 process,1 thread. It has no ambient Memory grant:
actual accepted message delivery must install the attachment.

The normal server validates the typed body and tests READ allowed with WRITE and
DERIVE denied before returning the same attachment. The delay variant waits past
the actual protected incoming deadline, retains a late reply's handle, then
rejects both the old serial and old object against a new request before returning
that new request's proper capability. Separate actual-fault, hold-before-receive
and fault-before-receive artifacts distinguish delivered ownership from queued
escrow recovery. Queued variants query the protected deadline before RECEIVE;
that query transfers no attachment.

The trusted controller observes actual faults, waits, ownership outcomes and
client Exit0. This actor does not emit synthetic Ready or refund evidence.
