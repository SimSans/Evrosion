//! Independent codec/actual upstream Session models only; these are not VM
//! execution, hardware, lease-authority or whole-negative acceptance evidence.
use super::*;
use ev_net_driver::{
    control::{Initialization, Notice, Operation, Packet, Status},
    network::Session,
    protocol::Window,
};
use ev_net_stack::stack::{Storage, TcpStatus};

#[derive(Clone)]
struct Memory([u8; 4096]);
impl Window for Memory {
    type Error = ();
    fn read(&mut self, n: usize) -> core::result::Result<u8, ()> {
        self.0.get(n).copied().ok_or(())
    }
    fn write(&mut self, n: usize, b: u8) -> core::result::Result<(), ()> {
        *self.0.get_mut(n).ok_or(())? = b;
        Ok(())
    }
}
fn row(window: &Memory, notice: Notice, reply: Option<Status>, sequence: u64) -> Row {
    let body = &window.0[64..];
    let request = u64::from_le_bytes(notice.encode().unwrap());
    Row {
        sequence,
        kind: if reply.is_some() { 3 } else { 2 },
        actor: if reply.is_some() { 8 } else { 0 },
        process: if reply.is_some() { 8 } else { 1 },
        thread: if reply.is_some() { 108 } else { 101 },
        tick: 100 + sequence,
        call: Some(records::Call {
            epoch: 501,
            id: u64::from(notice.sequence),
            endpoint: 45,
            ticket: u64::from(notice.sequence),
            deadline: 1000,
            caller: (1, 101),
            callee: (8, 108),
        }),
        opcode: notice.operation as u64,
        status: reply.unwrap_or(Status::Complete) as u64,
        length: u64::from(u16::from_le_bytes(window.0[14..16].try_into().unwrap())),
        value: u64::from_le_bytes(body[..8].try_into().unwrap()),
        request,
        payload: Sha256::digest(window.0).into(),
        image: [if reply.is_some() { 9 } else { 1 }; 32],
    }
}
fn exchange(
    session: &mut Session<'_>,
    op: Operation,
    sequence: u32,
    body: &[u8],
    rows: &mut Vec<Row>,
) -> Status {
    let notice = Notice {
        operation: op,
        sequence,
    };
    let mut packet = Packet::new();
    let mut memory = Memory([0; 4096]);
    packet.write_request(&mut memory, notice, body).unwrap();
    rows.push(row(&memory, notice, None, rows.len() as u64 + 1));
    let result = session.handle(&mut memory, notice, &mut packet).unwrap();
    let status = notice.response_status(result).unwrap();
    packet.read_response(&mut memory, notice, status).unwrap();
    rows.push(row(&memory, notice, Some(status), rows.len() as u64 + 1));
    status
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn dhcp(xid: [u8; 4], kind: u8) -> Vec<u8> {
    let mut p = vec![0; 240];
    p[..4].copy_from_slice(&[2, 1, 6, 0]);
    p[4..8].copy_from_slice(&xid);
    p[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    p[16..20].copy_from_slice(&[10, 0, 2, 15]);
    p[20..24].copy_from_slice(&[10, 0, 2, 2]);
    p[28..34].copy_from_slice(&ev_net_driver::REFERENCE_MAC);
    p[236..240].copy_from_slice(&[99, 130, 83, 99]);
    p.extend_from_slice(&[
        53, 1, kind, 54, 4, 10, 0, 2, 2, 51, 4, 0, 0, 14, 16, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0,
        2, 2, 6, 4, 10, 0, 2, 3, 255,
    ]);
    let mut f = vec![0; 42];
    f[..6].fill(255);
    f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    f[12..14].copy_from_slice(&[8, 0]);
    f[14] = 0x45;
    f[16..18].copy_from_slice(&((28 + p.len()) as u16).to_be_bytes());
    f[22] = 64;
    f[23] = 17;
    f[26..30].copy_from_slice(&[10, 0, 2, 2]);
    f[30..34].fill(255);
    f[34..36].copy_from_slice(&67u16.to_be_bytes());
    f[36..38].copy_from_slice(&68u16.to_be_bytes());
    f[38..40].copy_from_slice(&((8 + p.len()) as u16).to_be_bytes());
    let c = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    f.extend_from_slice(&p);
    f
}
fn configure(session: &mut Session<'_>) {
    session.stack().turn(0).unwrap();
    let discover = session
        .stack()
        .device()
        .begin_tx()
        .unwrap()
        .unwrap()
        .to_vec();
    let xid = discover[46..50].try_into().unwrap();
    session.stack().device().complete_tx().unwrap();
    session.stack().device().enqueue_rx(&dhcp(xid, 2)).unwrap();
    session.stack().turn(1).unwrap();
    let request = session
        .stack()
        .device()
        .begin_tx()
        .unwrap()
        .unwrap()
        .to_vec();
    assert_eq!(&request[46..50], &xid);
    session.stack().device().complete_tx().unwrap();
    session.stack().device().enqueue_rx(&dhcp(xid, 5)).unwrap();
    session.stack().turn(2).unwrap();
    assert_eq!(
        session.stack().lease().unwrap().address.address().octets(),
        [10, 0, 2, 15]
    );
}
fn arp() -> Vec<u8> {
    let mut b = vec![0; 42];
    b[..6].copy_from_slice(&ev_net_driver::REFERENCE_MAC);
    b[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    b[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    b[22..28].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    b[28..32].copy_from_slice(&[10, 0, 2, 2]);
    b[32..38].copy_from_slice(&ev_net_driver::REFERENCE_MAC);
    b[38..42].copy_from_slice(&[10, 0, 2, 15]);
    b
}
fn tcp(sequence: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 54];
    b[..6].copy_from_slice(&ev_net_driver::REFERENCE_MAC);
    b[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    b[12..14].copy_from_slice(&[8, 0]);
    b[14] = 0x45;
    b[16..18].copy_from_slice(&((40 + data.len()) as u16).to_be_bytes());
    b[22] = 64;
    b[23] = 6;
    b[26..30].copy_from_slice(&[10, 0, 2, 2]);
    b[30..34].copy_from_slice(&[10, 0, 2, 15]);
    b[34..36].copy_from_slice(&8080u16.to_be_bytes());
    b[36..38].copy_from_slice(&49152u16.to_be_bytes());
    b[38..42].copy_from_slice(&sequence.to_be_bytes());
    b[42..46].copy_from_slice(&ack.to_be_bytes());
    b[46] = 0x50;
    b[47] = flags;
    b[48..50].copy_from_slice(&4096u16.to_be_bytes());
    b.extend_from_slice(data);
    let c = checksum(&b[14..34]);
    b[24..26].copy_from_slice(&c.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&b[26..34]);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((20 + data.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&b[34..]);
    let c = checksum(&pseudo);
    b[50..52].copy_from_slice(&c.to_be_bytes());
    b
}
fn establish(session: &mut Session<'_>) -> u32 {
    session.stack().turn(3).unwrap();
    while session.stack().device().begin_tx().unwrap().is_some() {
        session.stack().device().complete_tx().unwrap();
    }
    session.stack().device().enqueue_rx(&arp()).unwrap();
    session.stack().turn(4).unwrap();
    let syn = session
        .stack()
        .device()
        .begin_tx()
        .unwrap()
        .unwrap()
        .to_vec();
    assert_eq!(syn[23], 6);
    assert_eq!(syn[47] & 2, 2);
    let initial = u32::from_be_bytes(syn[38..42].try_into().unwrap());
    session.stack().device().complete_tx().unwrap();
    session
        .stack()
        .device()
        .enqueue_rx(&tcp(1000, initial.wrapping_add(1), 0x12, &[]))
        .unwrap();
    session.stack().turn(5).unwrap();
    assert_eq!(
        session.stack().tcp_status().unwrap(),
        TcpStatus::Established
    );
    while session.stack().device().begin_tx().unwrap().is_some() {
        session.stack().device().complete_tx().unwrap();
    }
    initial
}
fn with_session(f: impl FnOnce(&mut Session<'_>)) {
    let mut body = [0; 40];
    body[..8].copy_from_slice(&123u64.to_le_bytes());
    body[8..12].copy_from_slice(&[10, 0, 2, 2]);
    body[12..14].copy_from_slice(&8080u16.to_le_bytes());
    body[14..16].copy_from_slice(&49152u16.to_le_bytes());
    body[16] = 16;
    body[24..].copy_from_slice(b"net.evrosion.dev");
    let mut storage = Storage::EMPTY;
    let mut session = Session::new(
        Initialization::parse(&body).unwrap(),
        7,
        0,
        storage.buffers(),
        1,
    )
    .unwrap();
    configure(&mut session);
    f(&mut session);
}
fn watch() -> Row {
    Row {
        sequence: 1,
        kind: 0,
        actor: 0,
        process: 1,
        thread: 101,
        tick: 100,
        call: None,
        opcode: 3,
        status: 0,
        length: 0,
        value: 1500,
        request: 0,
        payload: [0; 32],
        image: [1; 32],
    }
}
fn resequence(rows: &mut [Row]) {
    for (i, r) in rows.iter_mut().enumerate() {
        r.sequence = i as u64 + 1;
        r.tick = 100 + r.sequence;
    }
}
#[test]
fn actual_service_refusals_then_pending_connect_and_fresh_hello_match_real_codec_windows() {
    with_session(|session| {
        let mut rows = vec![watch()];
        for (seq, op, body) in [
            (2, Operation::Connect, &[10, 0, 2, 3, 0x90, 0x1f][..]),
            (3, Operation::Connect, &[10, 0, 2, 2, 0x91, 0x1f][..]),
            (4, Operation::Resolve, b"forbidden.invalid".as_slice()),
        ] {
            assert_eq!(exchange(session, op, seq, body, &mut rows), Status::Refused);
            assert_eq!(session.stack().tcp_status().unwrap(), TcpStatus::Closed);
        }
        assert_eq!(
            exchange(
                session,
                Operation::Connect,
                5,
                &[10, 0, 2, 2, 0x90, 0x1f],
                &mut rows
            ),
            Status::Pending
        );
        let initial = establish(session);
        assert_eq!(
            exchange(session, Operation::Write, 6, fixture::HELLO, &mut rows),
            Status::Complete
        );
        session.stack().turn(6).unwrap();
        let sent = session
            .stack()
            .device()
            .begin_tx()
            .unwrap()
            .unwrap()
            .to_vec();
        let h = 34 + usize::from(sent[46] >> 4) * 4;
        assert_eq!(&sent[h..], fixture::HELLO);
        session.stack().device().complete_tx().unwrap();
        let response = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                crate::network_fixture::HELLO.len()
            )
            .into_bytes(),
            crate::network_fixture::HELLO.to_vec(),
        ]
        .concat();
        session
            .stack()
            .device()
            .enqueue_rx(&tcp(
                1001,
                initial.wrapping_add(1 + fixture::HELLO.len() as u32),
                0x19,
                &response,
            ))
            .unwrap();
        session.stack().turn(7).unwrap();
        assert_eq!(
            exchange(
                session,
                Operation::Read,
                7,
                &1024u16.to_le_bytes(),
                &mut rows
            ),
            Status::Complete
        );
        assert_eq!(
            exchange(
                session,
                Operation::Read,
                8,
                &1024u16.to_le_bytes(),
                &mut rows
            ),
            Status::Complete
        );
        assert!(destination(&rows).unwrap());
        let mut bad = rows.clone();
        bad.iter_mut()
            .find(|r| r.kind == 3 && r.opcode == 5 && r.status == 1)
            .unwrap()
            .status = 0;
        assert!(destination(&bad).is_err());
        let mut bad = rows.clone();
        bad.iter_mut()
            .find(|r| r.kind == 2 && r.opcode == 5)
            .unwrap()
            .payload[0] ^= 1;
        assert!(!destination(&bad).unwrap());
        let mut bad = rows.clone();
        let r = bad
            .iter()
            .find(|r| r.kind == 2 && r.opcode == 5)
            .unwrap()
            .clone();
        bad.push(r);
        resequence(&mut bad);
        assert!(destination(&bad).is_err());
        let mut bad = rows;
        bad.iter_mut()
            .find(|r| r.kind == 2 && r.opcode == 6)
            .unwrap()
            .call
            .as_mut()
            .unwrap()
            .deadline = 1501;
        assert!(destination(&bad).is_err());
    });
}
#[test]
fn actual_established_socket_withholds_response_and_real_read_pending_is_required() {
    with_session(|session| {
        let mut rows = vec![watch()];
        assert_eq!(
            exchange(
                session,
                Operation::Connect,
                2,
                &[10, 0, 2, 2, 0x90, 0x1f],
                &mut rows
            ),
            Status::Pending
        );
        let _ = establish(session);
        assert_eq!(
            exchange(session, Operation::Status, 3, &[], &mut rows),
            Status::Complete
        );
        assert_eq!(
            exchange(session, Operation::Write, 4, fixture::PENDING, &mut rows),
            Status::Complete
        );
        assert_eq!(
            exchange(
                session,
                Operation::Read,
                5,
                &1024u16.to_le_bytes(),
                &mut rows
            ),
            Status::Pending
        );
        assert!(pending(&rows).unwrap());
        assert!(link_loss_scope(&rows).unwrap());
        let mut armed = rows.clone();
        let mut extra = watch();
        extra.opcode = 1;
        armed.push(extra);
        assert!(link_loss_scope(&armed).is_err());
        let mut lost = rows.clone();
        lost.retain(|r| r.kind != 0);
        assert!(!link_loss_scope(&lost).unwrap());

        let mut bad = rows.clone();
        bad.retain(|r| !(r.kind == 3 && r.opcode == 7));
        assert!(!pending(&bad).unwrap());
        let mut bad = rows.clone();
        bad.iter_mut()
            .find(|r| r.kind == 3 && r.opcode == 2)
            .unwrap()
            .value ^= 1 << 16;
        assert!(!pending(&bad).unwrap());
        let mut bad = rows;
        bad.iter_mut()
            .find(|r| r.kind == 3 && r.opcode == 7)
            .unwrap()
            .payload[31] ^= 1;
        assert!(!pending(&bad).unwrap());
    });
}
