//! Kernel-executed asynchronous mailbox proof, not a userspace IPC ABI.
use ev_kernel::{
    capability::{Authority, Kind, Rights},
    ipc::{Error, MAX_MESSAGES, Mailbox, Outgoing, Reclaimed},
    time::Deadline,
};
pub fn prove() {
    let mut authority = Authority::new();
    let sender = authority.create_space().unwrap();
    let receiver = authority.create_space().unwrap();
    let receive = authority
        .create_root(
            receiver,
            Kind::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::CONTROL | Rights::DERIVE | Rights::TRANSFER,
        )
        .unwrap();
    let send = authority
        .derive(receiver, receive, sender, Rights::SEND)
        .unwrap();
    let mut mailbox = Mailbox::new(&mut authority, receiver, receive).unwrap();
    let memory = authority
        .create_root(sender, Kind::Memory, Rights::READ | Rights::TRANSFER)
        .unwrap();
    let deadline = Deadline::after(0, 10).unwrap();
    for _ in 0..MAX_MESSAGES {
        mailbox
            .send(
                &mut authority,
                sender,
                send,
                Outgoing {
                    bytes: b"fill",
                    capability: None,
                    deadline,
                },
                0,
            )
            .unwrap();
    }
    assert_eq!(
        mailbox.send(
            &mut authority,
            sender,
            send,
            Outgoing {
                bytes: b"blocked",
                capability: Some(memory),
                deadline
            },
            0
        ),
        Err(Error::Full)
    );
    assert!(
        authority
            .authorize(sender, memory, Kind::Memory, Rights::READ)
            .is_ok()
    );
    for _ in 0..MAX_MESSAGES {
        let got = mailbox
            .receive(&mut authority, receiver, receive, 0)
            .unwrap();
        assert_eq!(&got.bytes[..got.length], b"fill");
    }
    mailbox
        .send(
            &mut authority,
            sender,
            send,
            Outgoing {
                bytes: b"deliver",
                capability: Some(memory),
                deadline,
            },
            0,
        )
        .unwrap();
    assert!(
        authority
            .authorize(sender, memory, Kind::Memory, Rights::READ)
            .is_err()
    );
    let got = mailbox
        .receive(&mut authority, receiver, receive, 1)
        .unwrap();
    assert_eq!(&got.bytes[..got.length], b"deliver");
    assert!(
        authority
            .authorize(
                receiver,
                got.capability.unwrap(),
                Kind::Memory,
                Rights::READ
            )
            .is_ok()
    );
    let memory = authority
        .create_root(sender, Kind::Memory, Rights::READ | Rights::TRANSFER)
        .unwrap();
    let ticket = mailbox
        .send(
            &mut authority,
            sender,
            send,
            Outgoing {
                bytes: b"expires",
                capability: Some(memory),
                deadline: Deadline::after(0, 2).unwrap(),
            },
            1,
        )
        .unwrap();
    assert_eq!(
        mailbox.receive(&mut authority, receiver, receive, 2),
        Err(Error::Expired)
    );
    let Reclaimed::Capability(back) = mailbox.reclaim(&mut authority, sender, ticket, 2).unwrap()
    else {
        panic!("missing timeout rollback")
    };
    assert!(
        authority
            .authorize(sender, back, Kind::Memory, Rights::READ)
            .is_ok()
    );
    let ticket = mailbox
        .send(
            &mut authority,
            sender,
            send,
            Outgoing {
                bytes: b"death",
                capability: Some(back),
                deadline,
            },
            2,
        )
        .unwrap();
    mailbox.receiver_died(receiver).unwrap();
    assert_eq!(
        mailbox.receive(&mut authority, receiver, receive, 2),
        Err(Error::Closed)
    );
    let Reclaimed::Capability(back) = mailbox.reclaim(&mut authority, sender, ticket, 2).unwrap()
    else {
        panic!("missing death rollback")
    };
    assert!(
        authority
            .authorize(sender, back, Kind::Memory, Rights::READ)
            .is_ok()
    );
    assert_eq!(
        mailbox.reclaim(&mut authority, sender, ticket, 2),
        Err(Error::InvalidTicket)
    );
    assert_eq!(mailbox.pending(), 0);
}
