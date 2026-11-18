# Userspace NE2000 PIO adapter

Actual byte-register driver code for the conditionally qualified QEMU ISA
NE2000 profile from [ADR-0058](../../architecture/adr/ADR-0058-bounded-isa-network-device.md).
This safe `no_std` library uses a `Ports` boundary; `Mediated` executes only the
existing checked PORT_INPUT35/PORT_OUTPUT36 syscalls. The Kernel must provide
the actual live device-scoped capability. Protocols, address configuration,
destination permissions, DNS and TCP do not belong in this adapter.

`Driver` performs bounded exclusive initialization, PROM/expected-MAC validation,
packet-RAM scrub and readback, start, synchronous TX, one-frame RX and stop/scrub.
Every I/O step checks the same absolute deadline and a finite step budget. It
yields periodically. Any uncertain/mutating failure quarantines the instance;
an attempted TX command is never retried or labelled remote delivery.

Before scrub, STOP is verified and byte mode plus full16KiB device-local transfer
bounds are restored and read back. Otherwise an old ring's wrap registers could
make a long zero/readback operation repeatedly visit a tiny region. All owned
packet RAM is then overwritten and independently checked. Unrelated lower PROM
and device address ranges are not made into guest physical memory.

`receive` returns a frame only after validating its header/producer extent,
copying every bounded span and checking fresh overflow status. Partial output
on error must not be published. Consumer advancement happens after copying.
`Failure.progress` describes outgoing-frame submission only; `NoFrameSubmitted`
does not mean all device state is unchanged.

The supervisor still owns dispatch fencing, revocation, real outstanding-work
retirement and replacement admission. Cooperative local stop cannot retract
already emitted host/remote packets or replace that lifecycle proof. Downstream
QEMU source qualification and actual packet/stop/failure execution remain open.

The explicit `probe` executable uses the existing v1 readonly startup at page509,
exactly selector1 IoPorts kind7/RW3, and the fixed local-development MAC
`02:45:56:52:00:01`. Its separate measured16KiB stack has guard gaps. The probe
only initializes, starts and stops. It is not the future network-service RPC
loop and is not run automatically by ordinary builds.

The separate `driver-service` image implements the real protected-RPC adapter.
It cold-prepares the device before binding its receiver and sending `EVNDRDY1`.
Its exact v1 child roles are ports1(kind7/rights3), NICWindow2(kind1/7),
DriverRPC3(kind2/272), RootEvents4(kind2/8). NICWindow is page508; the actual
producer must provide/check that mapping. `protocol` specifies one canonical
4096-byte window, a fresh u32 sequence, and Init/Start/Transmit/Poll/Stop. The
existing runtime captures/replies with the actual Kernel nonce. Real inherited
RPC deadlines remain at most1024ticks; Stop/readback must still be measured
under that bound, with quarantine on failure. No successful retirement is
inferred merely from a cooperative request or process exit.

`ev-net-service --features stack-executable` is a distinct protocol/policy image.
It holds no ports: NICWindow1(kind1/7), DriverRPC2(kind2/8), ClientWindow3(kind1/7),
ClientRPC4(kind2/272), RootEvents5(kind2/8). Its two windows are distinct pages508
and507. The fixed22,408-byte stack backing is private measured ELF data, borrowed
once; upstream nonzero empty values are preserved instead of zero-casting Rust
socket types. No heap or equivalent large runtime stack temporary is introduced.

ClientRPC SEND belongs only to the trusted Root controller for this Internal
integration. `control` defines canonical `EVNET001` frames and scalar notices;
commands are Initialize1, Status2, Resolve3, QueryResult4, Connect5, Write6,
Read7 and Close8. It sends `EVNSWAIT` after binding and refuses to construct
the stack until one initialization request provides an actual qualified-source
seed and a fixed DNS name/IP/remote-port/local-port scope. A scalar seed is not
an entropy proof. Root must not delegate this initialization route to an app.
The service sends `EVNSRDY1` only after actual Driver Start acknowledgement;
that event does not claim a DHCP lease or remote response.

`network::Session` reports actual DHCP/TCP state, keeps the diagnostic DNS name
separate from the exact allowed TCP destination, and accepts at most1024bytes
per write/read. A DNS answer is reported as data and cannot expand that scope.
Writes return exactly the queued prefix; reads before a connection are refused.
An unused/failed-SYN socket is not labelled a successful empty server response.
`pump` uses the existing RPC transport, one TX/one RX per turn and private queue
slots. Unknown TX keeps bytes pinned and blocks further window writes/retries.
Actual cancellation/stop/rebind still belongs to the supervisor and Kernel.

`clock` explicitly converts current nominal PIT IRQ ticks using divisor1193 and
the selected QEMU1193182Hz source. It provides no UTC, pause/interrupt-loss wall
time guarantee or completed M6-05 qualification. Neither executable uses a
constant production random seed; the real seed provider remains to be integrated.
Actual Kernel/Root graph admission, DHCP/DNS/TCP execution, app/forbidden-target
denials and device retirement remain pending guest acceptance.

```bash
cargo test --locked --offline -p ev-net-driver
cargo clippy --all-targets --locked --offline -p ev-net-driver -- -D warnings
cargo clippy --target x86_64-unknown-none --features probe --bin ev-net-driver --locked --offline -p ev-net-driver -- -D warnings
cargo test --locked --offline -p ev-net-driver --features stack-service
cargo clippy --target x86_64-unknown-none --features driver-service --bin ev-net-driver --locked --offline -p ev-net-driver -- -D warnings
cargo clippy --target x86_64-unknown-none --features stack-executable --bin ev-net-service --locked --offline -p ev-net-driver -- -D warnings
RUSTFLAGS='-C relocation-model=static -C code-model=large -C force-frame-pointers=yes -C link-arg=--no-pie' cargo build --release --target x86_64-unknown-none --features probe --bin ev-net-driver --locked --offline -p ev-net-driver
```

Fake-I/O tests run the same adapter source with hostile old wrap/word-mode state,
stale completion, failed readback, lost TX acknowledgement, overflow and clock
failure. They do not prove a real device or network path works.
