//! Bounded nonsecret failure classes, never authority or a quiescence witness.
//! NE8 = N/E/layer/operation/class/detail/subdetail/progress. No packet, shared
//! window, seed, address or capability bytes are included. Sender identity is
//! independently derived by the actual receiver/Kernel observation boundary.
use crate::{device, mediated};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostic([u8; 8]);
impl Diagnostic {
    pub fn checked(
        layer: u8,
        operation: u8,
        class: u8,
        detail: u8,
        subdetail: u8,
        progress: u8,
    ) -> Option<Self> {
        Self::decode([
            b'N', b'E', layer, operation, class, detail, subdetail, progress,
        ])
    }
    pub fn decode(b: [u8; 8]) -> Option<Self> {
        let [_, _, layer, op, class, detail, sub, progress] = b;
        if b[..2] != *b"NE" {
            return None;
        }
        let valid = match layer {
            1 if (1..=7).contains(&op) && progress <= 1 => match class {
                1 => match detail {
                    1 | 2 | 4 => sub == 0,
                    3 => sub != 0,
                    _ => false,
                },
                2..=6 | 8..=10 | 12 => detail == 0 && sub == 0,
                7 => sub == 0,
                11 => (1..=13).contains(&detail) && sub == 0,
                _ => false,
            },
            2 if op <= 7 && progress == 0 => match class {
                1 | 2 | 5 => detail == 0 && sub == 0,
                3 => detail <= 7 && sub == 0,
                4 => match detail {
                    1 | 2 | 4..=6 => sub == 0,
                    3 => sub != 0,
                    _ => false,
                },
                6 => (2..=7).contains(&detail) && sub == 0,
                7 => (1..=9).contains(&detail) && sub == 0,
                8 => (1..=5).contains(&detail) && sub == 0,
                _ => false,
            },
            3 if (1..=11).contains(&op) && progress == 0 => match class {
                1..=6 | 8 => detail == 0 && sub == 0,
                7 => detail <= 5 && sub == 0,
                // Root transfer's independent step budget, not Client::Counter.
                // Detail is its last validated TCP status (255 means none);
                // subdetail is the actual retained count, never a new limit.
                9 => (detail <= 10 || detail == 255) && sub == 128,
                _ => false,
            },
            _ => false,
        };
        valid.then_some(Self(b))
    }
    pub const fn encode(self) -> [u8; 8] {
        self.0
    }
    pub const fn layer(self) -> u8 {
        self.0[2]
    }
    pub const fn operation(self) -> u8 {
        self.0[3]
    }
    pub const fn class(self) -> u8 {
        self.0[4]
    }
    pub const fn detail(self) -> u8 {
        self.0[5]
    }
    pub const fn subdetail(self) -> u8 {
        self.0[6]
    }
    pub const fn progress(self) -> u8 {
        self.0[7]
    }
}
fn status(value: u64) -> u8 {
    u8::try_from(value).unwrap_or(255)
}
pub fn mediated(error: &mediated::Error) -> (u8, u8) {
    match error {
        mediated::Error::Handle => (1, 0),
        mediated::Error::Port => (2, 0),
        mediated::Error::Denied(code) => (3, status(*code)),
        mediated::Error::Reply => (4, 0),
    }
}
pub fn rpc(error: &ev_userspace_runtime::rpc::Error) -> (u8, u8) {
    use ev_userspace_runtime::rpc::Error;
    match error {
        Error::Deadline => (1, 0),
        Error::BusyLimit => (2, 0),
        Error::Remote(code) => (3, status(*code)),
        Error::Clock(_) => (4, 0),
        Error::Yield(_) => (5, 0),
        Error::AbiViolation(_) => (6, 0),
    }
}
pub fn device<E>(
    operation: u8,
    failure: &device::Failure<E>,
    io: impl FnOnce(&E) -> (u8, u8),
) -> Option<Diagnostic> {
    use device::Error;
    let (class, detail, sub) = match &failure.error {
        Error::Io(e) => {
            let (d, s) = io(e);
            (1, d, s)
        }
        Error::State => (2, 0, 0),
        Error::Bounds => (3, 0, 0),
        Error::Mac => (4, 0, 0),
        Error::Prom => (5, 0, 0),
        Error::Readback => (6, 0, 0),
        Error::Device(isr) => (7, *isr, 0),
        Error::ClockReversed => (8, 0, 0),
        Error::Deadline => (9, 0, 0),
        Error::PollBudget => (10, 0, 0),
        Error::Counter => (12, 0, 0),
        Error::Protocol(error) => {
            use ev_net_device::ne2000::Error;
            let detail = match error {
                Error::FrameLength => 1,
                Error::Page => 2,
                Error::Status => 3,
                Error::Count => 4,
                Error::NextPage => 5,
                Error::NotStopped => 6,
                Error::InvalidBudget => 7,
                Error::TimedOut => 8,
                Error::ClockRegression => 9,
                Error::Exhausted => 10,
                Error::Stale => 11,
                Error::Busy => 12,
                Error::Quarantined => 13,
            };
            (11, detail, 0)
        }
    };
    Diagnostic::checked(
        1,
        operation,
        class,
        detail,
        sub,
        u8::from(failure.progress == device::Progress::MayHaveSubmitted),
    )
}
#[cfg(feature = "stack-service")]
pub fn pump<W, T>(
    operation: u8,
    error: &crate::pump::Error<W, T>,
    transport: impl FnOnce(&T) -> (u8, u8),
) -> Option<Diagnostic> {
    use crate::{
        protocol::{Error as Frame, Failure},
        pump::Error,
    };
    let (class, detail, sub) = match error {
        Error::Quarantined => (1, 0, 0),
        Error::Counter => (2, 0, 0),
        Error::Response => (5, 0, 0),
        Error::Window(Failure::Window(_)) => (3, 0, 0),
        Error::Window(Failure::Frame(e)) => (
            3,
            match e {
                Frame::Header => 1,
                Frame::Operation => 2,
                Frame::Status => 3,
                Frame::Sequence => 4,
                Frame::Length => 5,
                Frame::Reserved => 6,
                Frame::Join => 7,
            },
            0,
        ),
        Error::Transport(e) => {
            let (d, s) = transport(e);
            (4, d, s)
        }
        Error::Remote(s) => (6, *s as u8, 0),
        Error::Stack(e) => {
            use ev_net_stack::stack::Error;
            (
                7,
                match e {
                    Error::Identity => 1,
                    Error::Time => 2,
                    Error::Quarantined => 3,
                    Error::Capacity => 4,
                    Error::Query => 5,
                    Error::QueryPending => 6,
                    Error::StaleQuery => 7,
                    Error::Counter => 8,
                    Error::Connect => 9,
                },
                0,
            )
        }
        Error::Queue(e) => {
            use ev_net_stack::device::Error;
            (
                8,
                match e {
                    Error::Length => 1,
                    Error::Full => 2,
                    Error::Busy => 3,
                    Error::NoPending => 4,
                    Error::Quarantined => 5,
                },
                0,
            )
        }
    };
    Diagnostic::checked(2, operation, class, detail, sub, 0)
}

/// One retained diagnostic only. Expiry/regression drops this observation;
/// it never clears the actor's real failure, I/O loan or hardware debt.
pub struct Pending {
    diagnostic: Option<Diagnostic>,
    cut: u64,
    last: u64,
    attempted_at: Option<u64>,
}
impl Pending {
    pub fn pending(&self) -> bool {
        self.diagnostic.is_some()
    }
    pub fn new(diagnostic: Diagnostic, now: u64) -> Option<Self> {
        let cut = now.checked_add(512).filter(|v| *v != u64::MAX)?;
        Some(Self {
            diagnostic: Some(diagnostic),
            cut,
            last: now,
            attempted_at: None,
        })
    }
    /// The adapter makes at most one SEND attempt per ordinary loop/tick.
    /// Busy keeps these exact bytes and original cut; acceptance consumes once.
    pub fn bytes(&mut self, now: u64) -> Option<[u8; 8]> {
        if now < self.last || now >= self.cut {
            self.diagnostic = None;
        }
        self.last = now;
        if self.attempted_at == Some(now) {
            return None;
        }
        let bytes = self.diagnostic.map(Diagnostic::encode)?;
        self.attempted_at = Some(now);
        Some(bytes)
    }
    pub fn accepted(&mut self) {
        self.diagnostic = None;
    }
    pub fn discard(&mut self) {
        self.diagnostic = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_root_remote_golden_and_unknowns_are_rejected() {
        let d = Diagnostic::checked(3, 2, 7, 5, 0, 0).unwrap();
        assert_eq!(d.encode(), [b'N', b'E', 3, 2, 7, 5, 0, 0]);
        assert_eq!(Diagnostic::decode(d.encode()), Some(d));
        for bad in [
            [b'N', b'E', 0, 2, 7, 5, 0, 0],
            [b'N', b'E', 4, 2, 7, 5, 0, 0],
            [b'N', b'E', 3, 0, 7, 5, 0, 0],
            [b'N', b'E', 3, 12, 7, 5, 0, 0],
            [b'N', b'E', 3, 2, 0, 5, 0, 0],
            [b'N', b'E', 3, 2, 7, 6, 0, 0],
            [b'N', b'E', 3, 2, 7, 5, 1, 0],
            [b'N', b'E', 3, 2, 7, 5, 0, 1],
            [b'N', b'E', 1, 4, 11, 14, 0, 0],
            [b'N', b'E', 2, 4, 6, 1, 0, 0],
        ] {
            assert_eq!(Diagnostic::decode(bad), None);
        }
        assert_eq!(
            Diagnostic::checked(3, 2, 9, 2, 128, 0).unwrap().encode(),
            [b'N', b'E', 3, 2, 9, 2, 128, 0]
        );
        assert!(Diagnostic::checked(3, 2, 9, 255, 128, 0).is_some());
        for (tcp, count) in [(11, 128), (254, 128), (2, 127), (2, 129)] {
            assert!(Diagnostic::checked(3, 2, 9, tcp, count, 0).is_none());
        }
    }
    #[test]
    fn diagnostic_expiry_busy_acceptance_and_clock_regression_do_not_renew_cut() {
        let d = Diagnostic::checked(1, 4, 11, 4, 0, 0).unwrap();
        let mut p = Pending::new(d, 10).unwrap();
        assert_eq!(p.bytes(10), Some(d.encode()));
        assert_eq!(p.bytes(10), None); // no second attempt in the same real tick
        assert!(p.pending());
        assert_eq!(p.bytes(521), Some(d.encode()));
        assert_eq!(p.bytes(522), None);
        assert!(!p.pending());
        assert_eq!(p.bytes(523), None);
        let mut p = Pending::new(d, 10).unwrap();
        assert_eq!(p.bytes(11), Some(d.encode()));
        assert_eq!(p.bytes(10), None);
        assert_eq!(p.bytes(12), None);
        let mut p = Pending::new(d, 10).unwrap();
        p.accepted();
        assert_eq!(p.bytes(10), None);
        assert!(Pending::new(d, u64::MAX - 512).is_none());
    }
    #[test]
    fn device_projection_has_only_typed_class_and_progress_without_raw_error_bytes() {
        let d = device(
            3,
            &device::Failure {
                error: device::Error::Io(mediated::Error::Denied(256)),
                progress: device::Progress::MayHaveSubmitted,
            },
            mediated,
        )
        .unwrap();
        assert_eq!(d.encode(), [b'N', b'E', 1, 3, 1, 3, 255, 1]);
        let d = device::<()>(
            4,
            &device::Failure {
                error: device::Error::Protocol(ev_net_device::ne2000::Error::Count),
                progress: device::Progress::NoFrameSubmitted,
            },
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(d.encode(), [b'N', b'E', 1, 4, 11, 4, 0, 0]);
    }
    #[cfg(feature = "stack-service")]
    #[test]
    fn pump_projection_distinguishes_transport_frame_remote_and_local_queue_failures() {
        use crate::{
            protocol::{Error as Frame, Failure, Status},
            pump::Error,
        };
        let cases: [(Error<(), ev_userspace_runtime::rpc::Error>, [u8; 8]); 4] = [
            (
                Error::Transport(ev_userspace_runtime::rpc::Error::Deadline),
                [b'N', b'E', 2, 3, 4, 1, 0, 0],
            ),
            (
                Error::Window(Failure::Frame(Frame::Length)),
                [b'N', b'E', 2, 4, 3, 5, 0, 0],
            ),
            (
                Error::Remote(Status::Quarantined),
                [b'N', b'E', 2, 4, 6, 5, 0, 0],
            ),
            (
                Error::Queue(ev_net_stack::device::Error::Length),
                [b'N', b'E', 2, 0, 8, 1, 0, 0],
            ),
        ];
        for (error, expected) in cases {
            let operation = expected[3];
            assert_eq!(pump(operation, &error, rpc).unwrap().encode(), expected);
        }
    }
}
