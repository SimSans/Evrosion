# Userspace runtime

Internal no_std x86-64 startup and scalar syscall transport for separate service
executables. `call(number, a, b, c)` returns `Reply { status, value, capability }`.
RAX is status; RSI/RDX are explicit input/output operands for received payload
and capability. The kernel retains responsibility for handle validation, deadlines
and safe user entry/return. These wrappers mint no authority and interpret no wire
protocol. Host builds refuse to issue a host `int80` instruction.

Safe wrappers provide `send`, `receive`, `yield_now`, `inspect`, `monotonic` and
terminal `exit`. `SyncEndpoint` implements the generated synchronous client
transport with a finite absolute deadline; it rejects unexpected returned caps.
The only library unsafe instructions are the documented syscall boundary and the
UD2 fallback if exit returns. No allocation or pointer syscall is introduced.

Executable bins define `ev_user_main(record, length)` and use
`global_asm!(ev_userspace_runtime::start_assembly!())`. The literal-producing macro
shares one SysV entry/memory-intrinsic implementation; `START_ASSEMBLY` exposes the
same text for inspection. Entry aligns the private stack while preserving the
kernel-supplied RDI/RSI bootstrap arguments.
