# Capability Echo client proof actor

A source-built Rust/no_std process using the separate generated
[cap_echo@1 contract](../../idl/ev.test.cap_echo.v1.json) and
[shared userspace runtime](../../libs/userspace-runtime/src/cap_echo.rs).
Its exact startup roles are selector1/2 Memory READ|TRANSFER65, selector3 request
SEND and selector4 response RECEIVE|CONTROL. The measured development profile is
finite:512 CPU ticks,16 frames,1 process,1 thread.

Five separately measured executable variants exercise normal roundtrips,
accepted delivered timeout, actual peer death after delivery, queued timeout and
actual peer death before delivery. Success is actual Exit0 after typed ownership,
READ allowance, WRITE/DERIVE denial and old-handle denial assertions. The second
Memory object stays separate during timeout retry; no status boolean manufactures
ownership or a refund. Pending/revoked/invalid ABI states fail the proof rather
than pretending successful recovery.

This is an Internal transport acceptance actor, not a user-facing application,
Stable ABI, recovery UI or complete M2 acceptance claim.
