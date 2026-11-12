# Echo service

A separate Rust/no_std executable using generated `ev.test.echo@1` request and
response types. It accepts exactly two explicit startup grants: selector 3 is an
Endpoint with RECEIVE/CONTROL, and selector 4 is an Endpoint with SEND. It receives
one eight-byte typed request, validates it before the handler runs, and sends the
same `u32` value back. Empty receive queues yield; unexpected transport/protocol
failures exit with an observable code. The kernel owns deadline, queue, authority
and process-lifetime enforcement.

The executable uses the shared userspace runtime, guarded private ELF layout and
read-only bootstrap contract. `test-fault` is a separately measured build which
writes the unmapped zero page after its first accepted response; normal code
contains no such injection. The dispatcher also routes generated synchronous
requests to this server. Separate `test-delay` and `test-selective-fault` artifacts
exercise timeout/late replies and victim replacement with an unrelated live peer.
These are development acceptance artifacts; full Root recovery remains separate.

Exit codes 100–106 identify startup/transport/protocol failures; 199 is a userspace
panic. Host tests cover startup grant attenuation, wrong kinds/rights, extra grants,
truncation and zero handles. Integration evidence belongs in the canonical tracker
after actual source-built/QEMU execution.
