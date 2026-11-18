# Bounded network device helpers

Internal userspace helpers for the proposed QEMU ISA NE2000 reference path.
No dependency, heap allocation, unsafe code, I/O instruction or capability
minting is provided. This crate does not constitute an executing NIC driver.

The reviewed model's remote transfers address device-local RAM. `ne2000`
validates untagged Ethernet frame sizes, the four-byte receive header, producer
bounds and ring wrap before describing at most two bounded reads. TX remains
below RX RAM. The four-slot `packet::Pool` refuses saturation atomically and
checks both generation and actual lifecycle incarnation before access/release.
This local pool is not a shared Memory Object lifetime protocol.

`STOP_WRITES` and `verify_stopped` describe explicit stop/abort/mask operations.
Reading the reset port alone does not stop the selected model or scrub old RAM.
The supervisor must first fence and revoke the old device holder, finish its
actual instruction/operation boundary, then use exclusive authority to stop,
verify, scrub and reinitialize before reminting to a replacement. These helpers
cannot produce a hardware quiescence receipt. No accepted transmission is
retried after an uncertain result; the local transmitter is quarantined.

`PollBudget` preserves one absolute same-boot deadline and finite poll count;
clock regression and timeout latch failure. It is not a wall clock.

The caller must clear old TX status before starting a new actual command and
obtain fresh real register observations before reporting completion. TX success
means local device completion, not delivery to a remote application. Host and
remote packets may remain in flight after stop; all packets remain untrusted.

See [ADR-0058](../../architecture/adr/ADR-0058-bounded-isa-network-device.md) for
the pinned source witness, authority/resource boundaries and outstanding guest
execution requirements. No physical NIC or other emulator version is qualified.

```bash
cargo test --locked --offline -p ev-net-device
cargo clippy --all-targets --locked --offline -p ev-net-device -- -D warnings
```
