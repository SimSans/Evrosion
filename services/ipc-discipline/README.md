# Internal IPC discipline actor

One source-built Rust/no_std image per profile uses the existing generated
[cap-free Echo contract](../../idl/ev.test.echo.v1.json) and shared runtime.
It provides actual user execution for AF-IPC-001 through005; portable tests and
actual controller evidence remain separate. No M2 acceptance claim comes from
building this image alone.

The chain profile uses three primary threads in separate processes. A's actual
MutexCONTROL selector7 returns a kernel-bound lease; the generated client calls
while its guard is held and must be rejected before waiting. After explicit
release,A→B→C succeeds with the protected deadline. B's deadline extension and
C's synchronous callback into ancestor A must reject without accepting work.

The depth profile uses three processes with three actual threads each. Each
process has selectors1/2,3/4,5/6: incoming endpointRECEIVE|CONTROL272 and outgoing
next-request SEND8 per local role. Actual rank=process_index+3*local_role. Eight
request endpoints serve ranks1..8; rank0's unused incoming role aliases rank3 in
the same process, and rank8's outgoing role targets existing rank1. Actual thread
identity must still reject rank0 receiving from rank3's alias. Depth8 succeeds;
attempt9 must reject as DepthExceeded before ancestor or capacity checks.

Fixture entry data extends only this Internal test profile: truthful readonly
bootstrap record/length stay in RDI/RSI, assigned local_role0..2 is RDX, immutable
process_index0..2 is RCX. They select declared roles, never a PID, protection
domain, entry point or arbitrary stack. The kernel independently checks actual
thread assignment. Shared entry assembly preserves these registers.

Five PT_LOAD segments include private zero RW/NX pages at BASE+0x100000 and
+0x102000 for role1/2 stacks, with guard holes at +0xff000,+0x101000,+0x103000.
The ordinary role0 stack remains loader page511/guard510. Spawn32 selects only
a declared local role; the controller validates those exact measured stack tops.
Chain policy512ticks/16frames/1process/1thread; depth512/16/1/3. Source image and
resource limits are finite bringup profiles, not permanent product VM limits.

Only globalrank0 exits0 after the complete chain unwinds. Other threads park by
Yield until trusted graph termination, preserving existing process-wide EXIT
semantics. Every reply uses actual incoming endpointRX|CONTROL plus the exact
nonce returned by RECEIVE34; protected caller wakeup is bound to that CallId.
This adds no response endpoint or SEND grant and changes no capability-reply27.
