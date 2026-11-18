use super::*;
use crate::ata::{SessionDisk, SessionOutcome, SessionWindow};
use core::cell::{Cell, RefCell};
use ev_userspace_contract::block::{Request, Response};

#[derive(Clone, Copy)]
enum Trip {
    ReadWord(usize, u64),
    WriteWord(usize, u64),
    ReadIdle(u64),
}
struct Timed {
    bus: Bus,
    trip: Option<Trip>,
    read_words: usize,
    write_words: usize,
    reset_starts: Vec<u64>,
    reset_fails: bool,
    persist_each_word: bool,
    read_batches: usize,
    write_batches: usize,
}
impl Timed {
    fn new() -> Self {
        Self {
            bus: Bus::new(),
            trip: None,
            read_words: 0,
            write_words: 0,
            reset_starts: Vec::new(),
            reset_fails: false,
            persist_each_word: false,
            read_batches: 0,
            write_batches: 0,
        }
    }
}
// Add controlled clock/device events to the existing ATA test model. The
// actual SessionDisk/AtaPio algorithms are compiled unchanged.
impl Ports for Timed {
    fn input_words4(&mut self, port: u16, _deadline: u64) -> Result<u64, u64> {
        self.read_batches += 1;
        let mut value = 0;
        for word in 0..4 {
            value |= u64::from(self.input(port, 2)?) << (word * 16);
        }
        Ok(value)
    }
    fn output_words4(&mut self, port: u16, value: u64, _deadline: u64) -> Result<(), u64> {
        self.write_batches += 1;
        for word in 0..4 {
            self.output(port, 2, u32::from((value >> (word * 16)) as u16))?;
        }
        Ok(())
    }
    fn input(&mut self, port: u16, width: u8) -> Result<u32, u64> {
        let result = self.bus.input(port, width)?;
        if port == DATA && width == 2 && self.bus.commands.last() == Some(&READ) {
            self.read_words += 1;
            if let Some(Trip::ReadWord(word, tick)) = self.trip
                && self.read_words == word
            {
                self.trip = None;
                self.bus.now = tick;
            }
        }
        if port == CONTROL_PORT
            && width == 1
            && self.bus.commands.last() == Some(&READ)
            && self.bus.position == 512
            && let Some(Trip::ReadIdle(tick)) = self.trip
        {
            self.trip = None;
            self.bus.now = tick;
        }
        Ok(result)
    }
    fn output(&mut self, port: u16, width: u8, value: u32) -> Result<(), u64> {
        let writing = self.bus.writing;
        self.bus.output(port, width, value)?;
        if port == CONTROL_PORT && width == 1 {
            if value & 4 != 0 {
                self.reset_starts.push(self.bus.now);
            } else if self.reset_fails {
                self.bus.status = BUSY;
                self.bus.stuck = true;
            }
        }
        if port == DATA && width == 2 && writing {
            self.write_words += 1;
            if self.persist_each_word {
                let offset = self.bus.position - 2;
                self.bus.disk[self.bus.lba as usize][offset..offset + 2]
                    .copy_from_slice(&(value as u16).to_le_bytes());
            }
            if let Some(Trip::WriteWord(word, tick)) = self.trip
                && self.write_words == word
            {
                self.trip = None;
                self.bus.now = tick;
            }
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, u64> {
        self.bus.now()
    }
    fn yield_now(&mut self) -> Result<(), u64> {
        self.bus.yield_now()
    }
}
struct Window {
    bytes: RefCell<[u8; 512]>,
    snapshots: Cell<usize>,
    publishes: Cell<usize>,
}
impl Window {
    fn new(byte: u8) -> Self {
        Self {
            bytes: RefCell::new([byte; 512]),
            snapshots: Cell::new(0),
            publishes: Cell::new(0),
        }
    }
}
impl SessionWindow for Window {
    fn snapshot(&self) -> [u8; 512] {
        self.snapshots.set(self.snapshots.get() + 1);
        *self.bytes.borrow()
    }
    fn publish(&self, bytes: &[u8; 512]) {
        self.publishes.set(self.publishes.get() + 1);
        *self.bytes.borrow_mut() = *bytes;
    }
}
fn initialized() -> AtaPio<Timed> {
    let mut disk = AtaPio::new(Timed::new());
    disk.reset(1000).unwrap();
    disk.identify(1000).unwrap();
    disk.idle(1000).unwrap();
    disk
}
fn session(disk: AtaPio<Timed>) -> SessionDisk<Timed> {
    SessionDisk::new(disk).unwrap_or_else(|_| panic!("test initialized an idle identified owner"))
}

#[test]
fn session_data_uses_exactly64_bounded_batches_and_preserves_word_order() {
    let mut disk = initialized();
    disk.io.read_batches = 0;
    disk.io.write_batches = 0;
    let mut disk = session(disk);
    let window = Window::new(0x91);
    assert!(matches!(
        disk.command(Request::Read { sector: 0 }, &window, 1000),
        SessionOutcome::Complete(_)
    ));
    assert_eq!(*window.bytes.borrow(), SEED);
    *window.bytes.borrow_mut() = core::array::from_fn(|n| n as u8);
    assert!(matches!(
        disk.command(Request::Write { sector: 1 }, &window, 1000),
        SessionOutcome::Complete(_)
    ));
    let io = disk.into_inner().io;
    assert_eq!(
        (
            io.read_batches,
            io.write_batches,
            io.read_words,
            io.write_words
        ),
        (64, 64, 256, 256)
    );
    assert_eq!(io.bus.disk[1], core::array::from_fn(|n| n as u8));
}

#[test]
fn a_clock_cut_inside_one_batch_has_bounded_uncertainty_and_no_read_publication() {
    let mut disk = initialized();
    disk.io.trip = Some(Trip::ReadWord(1, 20));
    let mut disk = session(disk);
    let window = Window::new(0x91);
    assert!(matches!(
        disk.command(Request::Read { sector: 0 }, &window, 20),
        SessionOutcome::Recovered(Failure {
            error: Error::Deadline,
            progress: Progress::MayHaveExecuted
        })
    ));
    assert_eq!(window.publishes.get(), 0);
    assert_eq!(*window.bytes.borrow(), [0x91; 512]);
    let io = disk.into_inner().io;
    assert_eq!(io.read_words, 4);
    assert_eq!(io.bus.commands.iter().filter(|c| **c == READ).count(), 1);
}

#[test]
fn a_write_batch_prefix_stays_uncertain_and_is_not_rolled_back_or_replayed() {
    let mut disk = initialized();
    let original = disk.io.bus.disk[1];
    disk.io.trip = Some(Trip::WriteWord(1, 20));
    disk.io.persist_each_word = true;
    let mut disk = session(disk);
    let window = Window::new(0x6d);
    assert!(matches!(
        disk.command(Request::Write { sector: 1 }, &window, 20),
        SessionOutcome::Recovered(Failure {
            error: Error::Deadline,
            progress: Progress::MayHaveExecuted
        })
    ));
    assert_eq!((window.snapshots.get(), window.publishes.get()), (1, 0));
    let io = disk.into_inner().io;
    assert_eq!(io.write_words, 4);
    assert_eq!(&io.bus.disk[1][..8], &[0x6d; 8]);
    assert_eq!(&io.bus.disk[1][8..], &original[8..]);
    assert_eq!(io.bus.commands.iter().filter(|c| **c == WRITE).count(), 1);
    assert_eq!(io.bus.completed_flushes, 0);
}

#[test]
fn physical_completion_returns_the_original_logical_ack_across_every_route_profile() {
    use crate::desktop::Routes;
    let cases = [
        (Routes::new(256, 257).unwrap(), 256, 0, 16),
        (Routes::new(256, 257).unwrap(), 256, 13, 29),
        (Routes::new(256, 257).unwrap(), 257, 0, 32),
        (Routes::new(256, 257).unwrap(), 257, 29, 61),
        (Routes::new_native(256, 257).unwrap(), 256, 16, 64),
        (Routes::new_native(256, 257).unwrap(), 256, 32, 80),
        (Routes::new_native(256, 257).unwrap(), 256, 48, 96),
        (Routes::new_native(256, 257).unwrap(), 257, 0, 32),
        (Routes::new_session(256, 257).unwrap(), 256, 64, 112),
        (Routes::new_session(256, 257).unwrap(), 256, 77, 125),
        (Routes::new_session(256, 257).unwrap(), 257, 16, 48),
    ];
    for (routes, endpoint, logical, physical) in cases {
        for request in [
            Request::Read { sector: logical },
            Request::Write { sector: logical },
        ] {
            let operation = routes.resolve(endpoint, request.encode()).unwrap();
            let mut raw = initialized();
            raw.io.bus.lba_base = physical;
            let mut disk = session(raw);
            let window = Window::new(0x55);
            let SessionOutcome::Complete(reply) = disk.command(operation.physical, &window, 100)
            else {
                panic!("actual ATA model command should complete");
            };
            assert_eq!(
                reply,
                match request {
                    Request::Read { .. } => Response::Read { sector: physical },
                    _ => Response::Written { sector: physical },
                }
            );
            assert_eq!(operation.complete(reply), Some(request.success()));
            assert_ne!(reply, request.success());
            assert_eq!(operation.complete(Response::Error { code: 2 }), None);
            assert_eq!(
                operation.complete(Response::Read {
                    sector: physical + 1
                }),
                None
            );
            assert_eq!(operation.complete(Response::Flushed), None);
            let io = disk.into_inner().into_ports();
            assert_eq!(io.bus.regs[3], physical as u8);
        }
    }
}

#[test]
fn successful_commands_publish_after_completion_without_recovery_or_replay() {
    let mut disk = session(initialized());
    let window = Window::new(0x91);
    assert_eq!(
        disk.command(Request::Read { sector: 0 }, &window, 100),
        SessionOutcome::Complete(Response::Read { sector: 0 })
    );
    assert_eq!(*window.bytes.borrow(), SEED);
    *window.bytes.borrow_mut() = RECORD;
    assert_eq!(
        disk.command(Request::Write { sector: 1 }, &window, 100),
        SessionOutcome::Complete(Response::Written { sector: 1 })
    );
    assert_eq!(
        disk.command(Request::Flush, &window, 100),
        SessionOutcome::Complete(Response::Flushed)
    );
    assert_eq!((window.snapshots.get(), window.publishes.get()), (1, 1));
    let io = disk.into_inner().into_ports();
    assert_eq!(io.bus.commands, [IDENTIFY, READ, WRITE, FLUSH]);
    assert_eq!(io.reset_starts.len(), 1);
}

#[test]
fn already_expired_or_unbounded_request_touches_neither_window_nor_device() {
    for deadline in [0, 1, u64::MAX] {
        let mut disk = session(initialized());
        let window = Window::new(0x91);
        assert_eq!(
            disk.command(Request::Write { sector: 1 }, &window, deadline),
            SessionOutcome::Refused(Failure {
                error: Error::Deadline,
                progress: Progress::NotIssued
            })
        );
        assert_eq!((window.snapshots.get(), window.publishes.get()), (0, 0));
        let io = disk.into_inner().into_ports();
        assert_eq!(io.bus.commands, [IDENTIFY]);
        assert_eq!(io.reset_starts.len(), 1);
    }
}

#[test]
fn invalid_geometry_refuses_before_snapshot_or_device_and_uninitialized_owner_is_returned() {
    let raw = AtaPio::new(Timed::new());
    let Err(returned) = SessionDisk::new(raw) else {
        panic!("unidentified device cannot serve")
    };
    assert!(returned.into_ports().bus.trace.is_empty());
    let mut disk = session(initialized());
    let window = Window::new(0x55);
    for request in [
        Request::Read {
            sector: DISK_SECTORS,
        },
        Request::Write { sector: u32::MAX },
    ] {
        assert_eq!(
            disk.command(request, &window, 10),
            SessionOutcome::Refused(Failure {
                error: Error::Bounds,
                progress: Progress::NotIssued
            })
        );
    }
    assert_eq!((window.snapshots.get(), window.publishes.get()), (0, 0));
    let io = disk.into_inner().into_ports();
    assert_eq!(io.bus.commands, [IDENTIFY]);
    assert_eq!(io.reset_starts.len(), 1);
}

#[test]
fn mid_read_and_post_read_idle_expiry_never_publish_and_reset_before_refusal() {
    for trip in [Trip::ReadWord(8, 10), Trip::ReadIdle(10)] {
        let mut disk = initialized();
        disk.io.trip = Some(trip);
        let mut disk = session(disk);
        let window = Window::new(0x91);
        assert_eq!(
            disk.command(Request::Read { sector: 0 }, &window, 10),
            SessionOutcome::Recovered(Failure {
                error: Error::Deadline,
                progress: Progress::MayHaveExecuted
            })
        );
        assert_eq!(*window.bytes.borrow(), [0x91; 512]);
        assert_eq!((window.snapshots.get(), window.publishes.get()), (0, 0));
        let io = disk.into_inner().into_ports();
        assert_eq!(io.bus.commands, [IDENTIFY, READ, IDENTIFY]);
        assert_eq!(io.reset_starts, [0, 10]);
        assert_eq!(io.bus.status, READY);
        assert!(!io.bus.writing);
    }
}

#[test]
fn uncertain_partial_write_is_preserved_and_never_replayed_after_reset() {
    let mut disk = initialized();
    disk.io.trip = Some(Trip::WriteWord(8, 10));
    disk.io.persist_each_word = true;
    let mut disk = session(disk);
    let window = Window::new(0x55);
    assert_eq!(
        disk.command(Request::Write { sector: 1 }, &window, 10),
        SessionOutcome::Recovered(Failure {
            error: Error::Deadline,
            progress: Progress::MayHaveExecuted
        })
    );
    assert_eq!((window.snapshots.get(), window.publishes.get()), (1, 0));
    let io = disk.into_inner().into_ports();
    assert_eq!(io.bus.commands, [IDENTIFY, WRITE, IDENTIFY]);
    assert_eq!(io.write_words, 8);
    assert_eq!(&io.bus.disk[1][..16], &[0x55; 16]);
    assert_eq!(&io.bus.disk[1][16..], &[0; 496]);
    assert_eq!(io.bus.completed_flushes, 0);
}

#[test]
fn cleanup_uses_original_cut_and_permanent_quarantine_never_reaccepts_or_reuses() {
    for (tick, reset_fails) in [(1034, false), (10, true)] {
        let mut disk = initialized();
        disk.io.trip = Some(Trip::WriteWord(8, tick));
        disk.io.reset_fails = reset_fails;
        let mut disk = session(disk);
        let window = Window::new(0x55);
        let first = disk.command(Request::Write { sector: 1 }, &window, 10);
        let SessionOutcome::Quarantined(quarantine) = first else {
            panic!("failed cleanup cannot ACK reusable backing")
        };
        assert_eq!(
            quarantine.operation,
            Failure {
                error: Error::Deadline,
                progress: Progress::MayHaveExecuted
            }
        );
        assert_eq!(quarantine.cleanup.error, Error::Deadline);
        assert_eq!(
            disk.command(Request::Read { sector: 0 }, &window, 1_000_000),
            first
        );
        assert_eq!(disk.command(Request::Flush, &window, 2_000_000), first);
        assert_eq!((window.snapshots.get(), window.publishes.get()), (1, 0));
        let io = disk.into_inner().into_ports();
        assert_eq!(io.bus.commands, [IDENTIFY, WRITE]);
        assert_eq!(io.bus.now, 1034);
        assert_eq!(io.write_words, 8);
        assert_eq!(io.reset_starts.len(), if reset_fails { 2 } else { 1 });
    }
}

#[test]
fn cleanup_overflow_cannot_wrap_into_new_time_or_issue_a_reset() {
    let mut disk = initialized();
    disk.io.bus.now = u64::MAX - 101;
    disk.io.trip = Some(Trip::ReadWord(8, u64::MAX - 100));
    let mut disk = session(disk);
    let window = Window::new(0x91);
    assert!(matches!(
        disk.command(Request::Read { sector: 0 }, &window, u64::MAX - 100),
        SessionOutcome::Quarantined(Quarantine {
            cleanup: Failure {
                error: Error::Deadline,
                progress: Progress::NotIssued
            },
            ..
        })
    ));
    assert_eq!(window.publishes.get(), 0);
    let io = disk.into_inner().into_ports();
    assert_eq!(io.bus.commands, [IDENTIFY, READ]);
    assert_eq!(io.reset_starts.len(), 1);
}
