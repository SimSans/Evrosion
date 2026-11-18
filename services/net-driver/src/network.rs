//! One fixed Root-authorized destination, one TCP socket and one DNS query.
//! Shared bytes are private snapshots; actual caller identity/credit and entropy
//! provisioning belong to the protected route and trusted source orchestration.
use crate::control::{ControlFailure, Initialization, Notice, Operation, Packet, Scope, Status};
use crate::protocol::Window;
use ev_net_stack::stack::{Buffers, Error as StackError, Query, Stack};

/// One service-incarnation's finite local ephemeral namespace. This metadata
/// never broadens the independently checked remote destination/name scope.
/// No Clone/Copy/default/reset operation can replenish the consumed range.
struct LocalPorts {
    next: Option<u16>,
}
impl LocalPorts {
    fn new(first: u16) -> Option<Self> {
        (first >= 49152).then_some(Self { next: Some(first) })
    }
    fn take(&mut self) -> Option<u16> {
        let port = self.next?;
        self.next = port.checked_add(1);
        Some(port)
    }
}

pub struct Session<'a> {
    stack: Stack<'a>,
    scope: Scope,
    sequence: u32,
    query: Option<Query>,
    resolved: bool,
    connect_requested: bool,
    established: bool,
    terminal: bool,
    shutdown_pending: bool,
    local_ports: LocalPorts,
}
impl<'a> Session<'a> {
    /// Call once from the actual trusted Root-only Initialize request, after the
    /// real provider has produced the seed. This constructor cannot prove that
    /// provider or time source by inspecting scalar values.
    pub fn new(
        init: Initialization,
        incarnation: u64,
        now_millis: u64,
        buffers: Buffers<'a>,
        initialize_sequence: u32,
    ) -> Result<Self, StackError> {
        if matches!(initialize_sequence, 0 | u32::MAX) {
            return Err(StackError::Identity);
        }
        let local_ports = LocalPorts::new(init.scope.local_port()).ok_or(StackError::Identity)?;
        let stack = Stack::new(
            incarnation,
            crate::REFERENCE_MAC,
            init.seed,
            now_millis,
            buffers,
        )?;
        Ok(Self {
            stack,
            scope: init.scope,
            sequence: initialize_sequence,
            query: None,
            resolved: false,
            connect_requested: false,
            established: false,
            terminal: false,
            shutdown_pending: false,
            local_ports,
        })
    }
    pub fn stack(&mut self) -> &mut Stack<'a> {
        &mut self.stack
    }
    pub fn terminal(&self) -> bool {
        self.terminal
    }
    /// Observe actual upstream state after each bounded pump turn. An unused
    /// Closed socket or failed SYN is not a successful empty server response.
    pub fn observe(&mut self) {
        use ev_net_stack::stack::TcpStatus;
        if self.connect_requested
            && matches!(
                self.stack.tcp_status(),
                Ok(TcpStatus::Established
                    | TcpStatus::CloseWait
                    | TcpStatus::FinWait1
                    | TcpStatus::FinWait2
                    | TcpStatus::Closing
                    | TcpStatus::LastAck
                    | TcpStatus::TimeWait)
            )
        {
            self.established = true;
        }
    }
    pub fn handle<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        packet: &mut Packet,
    ) -> Result<[u8; 8], ControlFailure<W::Error>> {
        if let Some(status) = self.accept(window, notice, packet, false)? {
            return packet.reply(window, notice, status, &[]);
        }
        let status = self.execute(notice.operation, packet);
        if status != Status::Complete {
            packet.length = 0;
        }
        packet.response(window, notice, status)
    }
    fn accept<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        packet: &mut Packet,
        terminal_allowed: bool,
    ) -> Result<Option<Status>, ControlFailure<W::Error>> {
        if self.terminal && !terminal_allowed {
            return Ok(Some(Status::Refused));
        }
        if self.sequence.checked_add(1) != Some(notice.sequence) {
            return Ok(Some(Status::Stale));
        }
        match packet.read_request(window, notice) {
            Ok(()) => {}
            Err(ControlFailure::Frame(_)) => {
                return Ok(Some(Status::Malformed));
            }
            Err(error) => return Err(error),
        }
        // Exactly once after complete canonical snapshot, before any socket or
        // query mutation. Replaying a write cannot append its payload twice.
        self.sequence = notice.sequence;
        Ok(None)
    }
    /// The executable supplies the actual protected Driver Stop operation.
    /// Latch terminal before invoking it: failure cannot resume packet pumping
    /// or authorize retry/replacement. Complete means actual Stop/scrub ACK.
    pub fn shutdown<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        packet: &mut Packet,
        stop: impl FnOnce() -> bool,
    ) -> Result<[u8; 8], ControlFailure<W::Error>> {
        if notice.operation != Operation::Shutdown {
            return packet.reply(window, notice, Status::Refused, &[]);
        }
        if let Some(status) = self.accept(window, notice, packet, false)? {
            return packet.reply(window, notice, status, &[]);
        }
        self.terminal = true;
        let status = if stop() {
            Status::Complete
        } else {
            Status::Uncertain
        };
        packet.reply(window, notice, status, &[])
    }
    /// Additive v2: terminal before the first driver operation. Pending means
    /// one actual quiescent chunk only; no normal stack pumping may resume.
    pub fn shutdown_v2<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        packet: &mut Packet,
        step: impl FnOnce(Option<u64>) -> Result<bool, ()>,
    ) -> Result<[u8; 8], ControlFailure<W::Error>> {
        if !matches!(
            notice.operation,
            Operation::ShutdownBegin | Operation::ShutdownStep
        ) {
            return packet.reply(window, notice, Status::Refused, &[]);
        }
        if let Some(status) = self.accept(window, notice, packet, true)? {
            return packet.reply(window, notice, status, &[]);
        }
        let begin = notice.operation == Operation::ShutdownBegin;
        if (begin && self.terminal) || (!begin && !self.shutdown_pending) {
            return packet.reply(window, notice, Status::Refused, &[]);
        }
        let aggregate = if begin {
            Some(u64::from_le_bytes(packet.data().try_into().unwrap()))
        } else {
            None
        };
        self.terminal = true;
        let status = match step(aggregate) {
            Ok(false) => {
                self.shutdown_pending = true;
                Status::Pending
            }
            Ok(true) => {
                self.shutdown_pending = false;
                Status::Complete
            }
            Err(()) => {
                self.shutdown_pending = false;
                Status::Uncertain
            }
        };
        packet.reply(window, notice, status, &[])
    }
    fn execute(&mut self, operation: Operation, packet: &mut Packet) -> Status {
        match operation {
            Operation::Initialize
            | Operation::Shutdown
            | Operation::ShutdownBegin
            | Operation::ShutdownStep => Status::Refused,
            Operation::Status => {
                packet.data.fill(0);
                packet.length = 32;
                packet.data[0] = 1;
                packet.data[2] = match self.stack.tcp_status() {
                    Ok(state) => state as u8,
                    Err(_) => return Status::Uncertain,
                };
                packet.data[3] = u8::from(self.query.is_some());
                packet.data[4] = u8::from(self.resolved);
                if let Some(lease) = self.stack.lease() {
                    packet.data[1] = 1;
                    packet.data[5] = lease.address.prefix_len();
                    packet.data[8..12].copy_from_slice(&lease.address.address().octets());
                    if let Some(router) = lease.router {
                        packet.data[12..16].copy_from_slice(&router.octets());
                    }
                    for (i, address) in lease.dns.into_iter().enumerate() {
                        if let Some(address) = address {
                            packet.data[16 + i * 4..20 + i * 4].copy_from_slice(&address.octets());
                        }
                    }
                }
                packet.data[24..26]
                    .copy_from_slice(&(self.stack.device().pending_rx() as u16).to_le_bytes());
                packet.data[26..28]
                    .copy_from_slice(&(self.stack.device().pending_tx() as u16).to_le_bytes());
                Status::Complete
            }
            Operation::Resolve => {
                if !self.scope.allows_name(packet.data()) || self.stack.lease().is_none() {
                    return Status::Refused;
                }
                if self.query.is_some() {
                    return Status::Pending;
                }
                self.resolved = false;
                match self.stack.query(self.scope.name()) {
                    Ok(query) => {
                        self.query = Some(query);
                        Status::Pending
                    }
                    Err(_) => Status::Refused,
                }
            }
            Operation::QueryResult => {
                let Some(query) = self.query else {
                    return Status::Refused;
                };
                match self.stack.query_result_v4(query) {
                    Err(StackError::QueryPending) => Status::Pending,
                    Err(_) => {
                        self.query = None;
                        self.resolved = false;
                        Status::Refused
                    }
                    Ok([None, None]) => {
                        self.query = None;
                        self.resolved = false;
                        Status::Refused
                    }
                    Ok(addresses) => {
                        self.query = None;
                        self.resolved = true;
                        packet.data[..4]
                            .copy_from_slice(&addresses.into_iter().flatten().next().unwrap());
                        packet.length = 4;
                        Status::Complete
                    }
                }
            }
            Operation::Connect => {
                if self.stack.lease().is_none() || !self.scope.allows_destination(packet.data()) {
                    return Status::Refused;
                }
                self.connect_scoped()
            }
            Operation::Write => {
                self.observe();
                if !self.connect_requested {
                    return Status::Refused;
                }
                if !self.established {
                    return Status::Pending;
                }
                match self.stack.tcp_send(packet.data()) {
                    Ok(Some(n)) if n > 0 => {
                        packet.data[..2].copy_from_slice(&(n as u16).to_le_bytes());
                        packet.length = 2;
                        Status::Complete
                    }
                    Ok(_) => Status::Pending,
                    Err(_) => Status::Refused,
                }
            }
            Operation::Read => {
                self.observe();
                if !self.connect_requested {
                    return Status::Refused;
                }
                if !self.established {
                    return Status::Pending;
                }
                let requested =
                    usize::from(u16::from_le_bytes(packet.data[..2].try_into().unwrap()));
                packet.data.fill(0);
                match self.stack.tcp_receive(&mut packet.data[..requested]) {
                    Ok(Some(n)) => {
                        packet.length = n;
                        Status::Complete
                    }
                    Ok(None) => Status::Pending,
                    Err(_) => Status::Refused,
                }
            }
            Operation::Close => match self.stack.close_tcp() {
                Ok(()) => {
                    packet.length = 0;
                    Status::Complete
                }
                Err(_) => Status::Refused,
            },
        }
    }
    fn connect_scoped(&mut self) -> Status {
        // Consume before attempting the socket transition. A refused/failed
        // attempt cannot make an earlier local tuple available again.
        let Some(local_port) = self.local_ports.take() else {
            return Status::Refused;
        };
        match self
            .stack
            .connect_v4(self.scope.address(), self.scope.remote_port(), local_port)
        {
            Ok(()) => {
                self.connect_requested = true;
                self.established = false;
                Status::Pending
            }
            Err(_) => Status::Refused,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ev_net_stack::stack::Storage;
    use std::vec::Vec;
    fn dhcp_reply(xid: [u8; 4], kind: u8) -> Vec<u8> {
        let mut payload = std::vec![0;240];
        payload[..4].copy_from_slice(&[2, 1, 6, 0]);
        payload[4..8].copy_from_slice(&xid);
        payload[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        payload[16..20].copy_from_slice(&[10, 0, 2, 15]);
        payload[20..24].copy_from_slice(&[10, 0, 2, 2]);
        payload[28..34].copy_from_slice(&crate::REFERENCE_MAC);
        payload[236..240].copy_from_slice(&[99, 130, 83, 99]);
        payload.extend_from_slice(&[
            53, 1, kind, 54, 4, 10, 0, 2, 2, 51, 4, 0, 0, 14, 16, 1, 4, 255, 255, 255, 0, 3, 4, 10,
            0, 2, 2, 6, 4, 10, 0, 2, 3, 255,
        ]);
        let mut bytes = std::vec![0;42];
        bytes[..6].fill(255);
        bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        bytes[12..14].copy_from_slice(&[8, 0]);
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        bytes[22] = 64;
        bytes[23] = 17;
        bytes[26..30].copy_from_slice(&[10, 0, 2, 2]);
        bytes[30..34].fill(255);
        bytes[34..36].copy_from_slice(&67u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&68u16.to_be_bytes());
        bytes[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        let mut sum = bytes[14..34]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum::<u32>();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        bytes[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }
    fn configure(session: &mut Session<'_>) {
        // Actual upstream DHCP state machine over its bounded RX/TX queues;
        // no production address/lease setter or network provider is invented.
        session.stack.turn(0).unwrap();
        let discover = session.stack.device().begin_tx().unwrap().unwrap().to_vec();
        let xid = discover[46..50].try_into().unwrap();
        session.stack.device().complete_tx().unwrap();
        session
            .stack
            .device()
            .enqueue_rx(&dhcp_reply(xid, 2))
            .unwrap();
        session.stack.turn(1).unwrap();
        let request = session.stack.device().begin_tx().unwrap().unwrap().to_vec();
        assert_eq!(&request[46..50], &xid);
        assert!(request[282..].windows(3).any(|p| p == [53, 1, 3]));
        session.stack.device().complete_tx().unwrap();
        session
            .stack
            .device()
            .enqueue_rx(&dhcp_reply(xid, 5))
            .unwrap();
        session.stack.turn(2).unwrap();
        assert_eq!(
            session.stack.lease().unwrap().address.address().octets(),
            [10, 0, 2, 15]
        );
    }
    struct Memory([u8; 4096]);
    impl Window for Memory {
        type Error = ();
        fn read(&mut self, n: usize) -> Result<u8, ()> {
            self.0.get(n).copied().ok_or(())
        }
        fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
            *self.0.get_mut(n).ok_or(())? = b;
            Ok(())
        }
    }
    fn connect(
        session: &mut Session<'_>,
        memory: &mut Memory,
        packet: &mut Packet,
        sequence: u32,
        last: u8,
    ) -> Status {
        let notice = Notice {
            operation: Operation::Connect,
            sequence,
        };
        packet
            .write_request(memory, notice, &[10, 0, 2, last, 0x90, 0x1f])
            .unwrap();
        notice
            .response_status(session.handle(memory, notice, packet).unwrap())
            .unwrap()
    }
    #[test]
    fn no_lease_or_wrong_destination_never_opens_a_socket_and_replay_refuses() {
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        for (sequence, data) in [(2, &b"other.test"[..]), (3, &b"net.evrosion.dev"[..])] {
            let notice = Notice {
                operation: Operation::Resolve,
                sequence,
            };
            packet.write_request(&mut memory, notice, data).unwrap();
            let result = session.handle(&mut memory, notice, &mut packet).unwrap();
            assert_eq!(notice.response_status(result), Ok(Status::Refused));
        }
        let notice = Notice {
            operation: Operation::Connect,
            sequence: 4,
        };
        packet
            .write_request(&mut memory, notice, &[10, 0, 2, 3, 0x90, 0x1f])
            .unwrap();
        let reply = session.handle(&mut memory, notice, &mut packet).unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Refused));
        assert_eq!(
            session.stack.tcp_status().unwrap(),
            ev_net_stack::stack::TcpStatus::Closed
        );
        let reply = session.handle(&mut memory, notice, &mut packet).unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Stale));
        assert_eq!(session.local_ports.next, Some(49152));
    }
    #[test]
    fn local_ephemeral_range_is_finite_monotone_and_never_wraps() {
        assert!(LocalPorts::new(0).is_none());
        assert!(LocalPorts::new(49151).is_none());
        let mut ports = LocalPorts::new(49152).unwrap();
        for expected in 49152..=u16::MAX {
            assert_eq!(ports.take(), Some(expected));
        }
        for _ in 0..4 {
            assert_eq!(ports.take(), None);
        }
    }
    #[test]
    fn actual_single_socket_uses_fresh_ports_after_failed_attempt_and_socket_retirement() {
        // Model only: actual upstream DHCP/one-socket state with bounded frames.
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        configure(&mut session);
        let (mut memory, mut packet) = (Memory([0; 4096]), Packet::new());
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 2, 3),
            Status::Refused
        );
        assert_eq!(session.local_ports.next, Some(49152));
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 3, 2),
            Status::Pending
        );
        assert_eq!(
            session.stack.tcp().unwrap().local_endpoint().unwrap().port,
            49152
        );
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 3, 2),
            Status::Stale
        );
        assert_eq!(session.local_ports.next, Some(49153));
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 4, 2),
            Status::Refused
        ); // existing SynSent socket
        assert_eq!(session.local_ports.next, Some(49154)); // failed attempt consumed49153
        assert_eq!(
            session.stack.tcp().unwrap().local_endpoint().unwrap().port,
            49152
        );
        // Host model retires the old socket. Production transport still uses
        // only its existing Close/EOF protocol, with no reset/abort addition.
        session.stack.tcp().unwrap().abort();
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 5, 2),
            Status::Pending
        );
        assert_eq!(
            session.stack.tcp().unwrap().local_endpoint().unwrap().port,
            49154
        );
        assert_eq!(session.local_ports.next, Some(49155));
    }
    #[test]
    fn exhaustion_and_malformed_or_reinitialized_controls_cannot_replenish_ports() {
        let mut body = crate::control::tests::initialization();
        body[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
        let init = Initialization::parse(&body).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        configure(&mut session);
        let (mut memory, mut packet) = (Memory([0; 4096]), Packet::new());
        let bad = Notice {
            operation: Operation::Connect,
            sequence: 2,
        };
        packet
            .write_request(&mut memory, bad, &[10, 0, 2, 3, 0x90, 0x1f])
            .unwrap();
        memory.0[12] = 1; // corrupt the canonical request sequence/header
        let reply = session.handle(&mut memory, bad, &mut packet).unwrap();
        assert_eq!(bad.response_status(reply), Ok(Status::Malformed));
        assert_eq!(session.local_ports.next, Some(u16::MAX));
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 2, 2),
            Status::Pending
        );
        assert_eq!(
            session.stack.tcp().unwrap().local_endpoint().unwrap().port,
            u16::MAX
        );
        assert_eq!(session.local_ports.next, None);
        session.stack.tcp().unwrap().abort();
        assert_eq!(
            connect(&mut session, &mut memory, &mut packet, 3, 2),
            Status::Refused
        );
        assert_eq!(
            session.stack.tcp_status().unwrap(),
            ev_net_stack::stack::TcpStatus::Closed
        );
        let initialize = Notice {
            operation: Operation::Initialize,
            sequence: 4,
        };
        packet
            .write_request(&mut memory, initialize, &body)
            .unwrap();
        let reply = session
            .handle(&mut memory, initialize, &mut packet)
            .unwrap();
        assert_eq!(initialize.response_status(reply), Ok(Status::Refused));
        assert_eq!(session.local_ports.next, None);
    }
    #[test]
    fn status_is_actual_unconfigured_state_and_initialize_cannot_rewrite_scope() {
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        let notice = Notice {
            operation: Operation::Status,
            sequence: 2,
        };
        packet.write_request(&mut memory, notice, &[]).unwrap();
        let reply = session.handle(&mut memory, notice, &mut packet).unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Complete));
        packet
            .read_response(&mut memory, notice, Status::Complete)
            .unwrap();
        assert_eq!(packet.data()[0], 1);
        assert_eq!(&packet.data()[1..24], &[0; 23]);
        let notice = Notice {
            operation: Operation::Initialize,
            sequence: 3,
        };
        packet
            .write_request(
                &mut memory,
                notice,
                &crate::control::tests::initialization(),
            )
            .unwrap();
        let reply = session.handle(&mut memory, notice, &mut packet).unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Refused));
        assert_eq!(session.scope.address(), [10, 0, 2, 2]);
    }
    #[test]
    fn shutdown_validates_full_snapshot_and_sequence_before_exactly_one_real_stop() {
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        let notice = Notice {
            operation: Operation::Shutdown,
            sequence: 2,
        };
        packet.write_request(&mut memory, notice, &[]).unwrap();
        memory.0[4095] = 1;
        let reply = session
            .shutdown(&mut memory, notice, &mut packet, || {
                panic!("malformed request must not stop hardware")
            })
            .unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Malformed));
        assert!(!session.terminal());
        packet.write_request(&mut memory, notice, &[]).unwrap();
        let mut stops = 0;
        let reply = session
            .shutdown(&mut memory, notice, &mut packet, || {
                stops += 1;
                true
            })
            .unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Complete));
        assert!(session.terminal());
        packet
            .read_response(&mut memory, notice, Status::Complete)
            .unwrap();
        let reply = session
            .shutdown(&mut memory, notice, &mut packet, || {
                stops += 1;
                true
            })
            .unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Refused));
        assert_eq!(stops, 1);
        let later = Notice {
            operation: Operation::Resolve,
            sequence: 3,
        };
        packet
            .write_request(&mut memory, later, b"net.evrosion.dev")
            .unwrap();
        assert_eq!(
            later.response_status(session.handle(&mut memory, later, &mut packet).unwrap()),
            Ok(Status::Refused)
        );
    }
    #[test]
    fn failed_stop_is_terminal_uncertain_and_never_authorizes_pump_or_retry() {
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        let notice = Notice {
            operation: Operation::Shutdown,
            sequence: 2,
        };
        packet.write_request(&mut memory, notice, &[]).unwrap();
        let reply = session
            .shutdown(&mut memory, notice, &mut packet, || false)
            .unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Uncertain));
        assert!(session.terminal());
        packet
            .read_response(&mut memory, notice, Status::Uncertain)
            .unwrap();
        let reply = session
            .shutdown(&mut memory, notice, &mut packet, || {
                panic!("accepted uncertain cleanup cannot replay")
            })
            .unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Refused));
    }

    #[test]
    fn continuation_latches_terminal_before_begin_and_ignores_replay_or_normal_work() {
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        let premature = Notice {
            operation: Operation::ShutdownStep,
            sequence: 2,
        };
        packet.write_request(&mut memory, premature, &[]).unwrap();
        let reply = session
            .shutdown_v2(&mut memory, premature, &mut packet, |_| {
                panic!("Step before Begin must not reach Driver")
            })
            .unwrap();
        assert_eq!(premature.response_status(reply), Ok(Status::Refused));
        assert!(!session.terminal());
        let begin = Notice {
            operation: Operation::ShutdownBegin,
            sequence: 3,
        };
        packet
            .write_request(&mut memory, begin, &8192u64.to_le_bytes())
            .unwrap();
        let reply = session
            .shutdown_v2(&mut memory, begin, &mut packet, |cut| {
                assert_eq!(cut, Some(8192));
                Ok(false)
            })
            .unwrap();
        assert_eq!(begin.response_status(reply), Ok(Status::Pending));
        assert!(session.terminal());
        // Replayed Begin cannot recapture or renew the original aggregate.
        packet
            .write_request(&mut memory, begin, &8193u64.to_le_bytes())
            .unwrap();
        let reply = session
            .shutdown_v2(&mut memory, begin, &mut packet, |_| {
                panic!("duplicate Begin")
            })
            .unwrap();
        assert_eq!(begin.response_status(reply), Ok(Status::Stale));
        let ordinary = Notice {
            operation: Operation::Status,
            sequence: 4,
        };
        packet.write_request(&mut memory, ordinary, &[]).unwrap();
        let reply = session.handle(&mut memory, ordinary, &mut packet).unwrap();
        assert_eq!(ordinary.response_status(reply), Ok(Status::Refused));
        for sequence in 4..=131 {
            let step = Notice {
                operation: Operation::ShutdownStep,
                sequence,
            };
            packet.write_request(&mut memory, step, &[]).unwrap();
            let reply = session
                .shutdown_v2(&mut memory, step, &mut packet, |cut| {
                    assert_eq!(cut, None);
                    Ok(sequence == 131)
                })
                .unwrap();
            assert_eq!(
                step.response_status(reply),
                Ok(if sequence == 131 {
                    Status::Complete
                } else {
                    Status::Pending
                })
            );
            assert!(session.terminal());
        }
        let later = Notice {
            operation: Operation::ShutdownStep,
            sequence: 132,
        };
        packet.write_request(&mut memory, later, &[]).unwrap();
        let reply = session
            .shutdown_v2(&mut memory, later, &mut packet, |_| {
                panic!("completed cleanup cannot restart")
            })
            .unwrap();
        assert_eq!(later.response_status(reply), Ok(Status::Refused));
    }

    #[test]
    fn failed_continuation_cannot_replay_unknown_chunk_or_restart_legacy_work() {
        let init = Initialization::parse(&crate::control::tests::initialization()).unwrap();
        let mut storage = Storage::EMPTY;
        let mut session = Session::new(init, 7, 0, storage.buffers(), 1).unwrap();
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        for (sequence, operation) in [(2, Operation::ShutdownBegin), (3, Operation::ShutdownStep)] {
            let notice = Notice {
                operation,
                sequence,
            };
            let body = 8192u64.to_le_bytes();
            packet
                .write_request(&mut memory, notice, if sequence == 2 { &body } else { &[] })
                .unwrap();
            let reply = session
                .shutdown_v2(&mut memory, notice, &mut packet, |_| {
                    if sequence == 2 { Ok(false) } else { Err(()) }
                })
                .unwrap();
            assert_eq!(
                notice.response_status(reply),
                Ok(if sequence == 2 {
                    Status::Pending
                } else {
                    Status::Uncertain
                })
            );
        }
        let notice = Notice {
            operation: Operation::ShutdownStep,
            sequence: 4,
        };
        packet.write_request(&mut memory, notice, &[]).unwrap();
        let reply = session
            .shutdown_v2(&mut memory, notice, &mut packet, |_| {
                panic!("uncertain chunk cannot retry")
            })
            .unwrap();
        assert_eq!(notice.response_status(reply), Ok(Status::Refused));
        assert!(session.terminal());
    }
}
