//! Host the exact kernel Wire implementation against real portable owners.
extern crate std;
use crate as ev_kernel;
#[cfg(feature = "test-m6-session")]
use crate::rpc::{CallId, Rpc};
use crate::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    ipc::{Error as IpcError, Mailbox, Outgoing, Ticket},
    scheduler::{ProcessId, Scheduler, ThreadId},
    service::Metadata,
    time::Deadline,
};
use ev_userspace_contract::root_v2;
// The production module also contains binding/diagnostic/lifecycle helpers;
// these focused checks host it unchanged without pretending to exercise them.
#[allow(dead_code)]
#[path = "wire.rs"]
mod wire;
use root_v2::graph::DeliveryMode;
use wire::Wire;

fn fixture(mode: DeliveryMode) -> (Authority, Scheduler, Metadata, Handle, Wire) {
    let mut authority = Authority::new();
    let domain = authority.create_space().unwrap();
    let cap = authority
        .create_root(
            domain,
            Kind::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap();
    let object = authority
        .authorize(domain, cap, Kind::Endpoint, Rights::CONTROL)
        .unwrap()
        .identity();
    let mailbox = Mailbox::new(&mut authority, domain, cap).unwrap();
    let mut scheduler = Scheduler::new();
    let job = scheduler.create_job().unwrap();
    let process = scheduler.create_process(job).unwrap();
    let thread = scheduler.create_thread(process).unwrap();
    (
        authority,
        scheduler,
        Metadata {
            domain,
            job,
            process,
            thread,
            frames: 0,
        },
        cap,
        Wire::new(object, domain, mailbox, mode),
    )
}

#[test]
fn rpc_wire_refuses_scalar_send_and_receive_without_accepting_or_consuming() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Rpc);
    let deadline = Deadline::after(0, 10).unwrap();
    assert_eq!(
        wire.send(&mut authority, meta, cap, 0x1234, deadline, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(wire.pending(), 0);
    let ticket = wire
        .send_rpc(&mut authority, meta, cap, 0x5678, deadline, 0)
        .unwrap();
    assert_eq!(
        wire.receive(&mut authority, meta, cap, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(wire.pending(), 1);
    let (delivery, process, thread) = wire.receive_rpc(&mut authority, meta, cap, 0).unwrap();
    assert_eq!(
        (delivery.ticket, process, thread),
        (ticket, meta.process, meta.thread)
    );
    assert_eq!(delivery.capability, None);
    assert_eq!(&delivery.bytes[..8], &0x5678u64.to_le_bytes());
    assert_eq!(wire.pending(), 0);
}

#[test]
fn async_wire_refuses_rpc_primitives_and_preserves_the_accepted_scalar_ticket() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let deadline = Deadline::after(0, 10).unwrap();
    assert_eq!(
        wire.send_rpc(&mut authority, meta, cap, 0x1234, deadline, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(wire.pending(), 0);
    let ticket = wire
        .send(&mut authority, meta, cap, 0x8765, deadline, 0)
        .unwrap();
    assert_eq!(
        wire.receive_rpc(&mut authority, meta, cap, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(wire.pending(), 1);
    let (delivery, process, thread) = wire.receive(&mut authority, meta, cap, 0).unwrap();
    assert_eq!(
        (delivery.ticket, process, thread),
        (ticket, meta.process, meta.thread)
    );
    assert_eq!(&delivery.bytes[..8], &0x8765u64.to_le_bytes());
}

#[test]
fn selected_route_does_not_become_scalar_send_rpc_or_ordinary_receive() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Selected);
    let deadline = Deadline::after(0, 10).unwrap();
    assert_eq!(
        wire.send(&mut authority, meta, cap, 3, deadline, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(
        wire.send_rpc(&mut authority, meta, cap, 4, deadline, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(
        wire.receive(&mut authority, meta, cap, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(
        wire.receive_rpc(&mut authority, meta, cap, 0),
        Err(IpcError::RestrictedBinding)
    );
    assert_eq!(wire.pending(), 0);
    assert!(
        authority
            .authorize(meta.domain, cap, Kind::Endpoint, Rights::CONTROL)
            .is_ok()
    );
}

#[test]
fn delivery_metadata_never_replaces_actual_endpoint_authorization() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let deadline = Deadline::after(0, 10).unwrap();
    let other = authority
        .create_root(
            meta.domain,
            Kind::Endpoint,
            Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap();
    assert_eq!(
        wire.send(&mut authority, meta, other, 3, deadline, 0),
        Err(IpcError::WrongEndpoint)
    );
    assert_eq!(wire.pending(), 0);
    let denied_domain = authority.create_space().unwrap();
    let denied = Metadata {
        domain: denied_domain,
        ..meta
    };
    assert!(
        wire.send(&mut authority, denied, cap, 4, deadline, 0)
            .is_err()
    );
    assert_eq!(wire.pending(), 0);
    wire.send(&mut authority, meta, cap, 5, deadline, 0)
        .unwrap();
    assert!(wire.receive(&mut authority, denied, cap, 0).is_err());
    assert_eq!(wire.pending(), 1);
    assert!(wire.receive(&mut authority, meta, cap, 0).is_ok());
}

#[cfg(feature = "test-m6-session")]
#[test]
fn exact_async_expiry_reopens_capacity_and_old_tickets_never_consume_later_messages() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let first = wire
        .send(
            &mut authority,
            meta,
            cap,
            19,
            Deadline::after(0, 5).unwrap(),
            0,
        )
        .unwrap();
    let later = wire
        .send(
            &mut authority,
            meta,
            cap,
            29,
            Deadline::after(0, 10).unwrap(),
            0,
        )
        .unwrap();
    assert!(
        wire.expire_async(&mut authority, 4)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    let receipts = wire.expire_async(&mut authority, 5).unwrap();
    let records = receipts.iter().flatten().collect::<std::vec::Vec<_>>();
    assert_eq!(records.len(), 1);
    assert_eq!(
        (
            records[0].message.ticket,
            records[0].process,
            records[0].thread
        ),
        (first, meta.process, meta.thread)
    );
    assert_eq!(u64::from_le_bytes(records[0].message.bytes), 19);
    assert_eq!((wire.pending(), wire.accepted_senders().count()), (1, 1));
    assert!(
        wire.expire_async(&mut authority, 5)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    let (received, _, _) = wire.receive(&mut authority, meta, cap, 5).unwrap();
    assert_eq!(received.ticket, later);
    assert_eq!(&received.bytes[..8], &29u64.to_le_bytes());
    assert_eq!((wire.pending(), wire.accepted_senders().count()), (0, 0));
    for value in 0..4 {
        wire.send(
            &mut authority,
            meta,
            cap,
            value,
            Deadline::after(5, 5).unwrap(),
            5,
        )
        .unwrap();
    }
    assert_eq!(wire.pending(), 4);
}

#[cfg(feature = "test-m6-session")]
#[test]
fn async_cleanup_leaves_rpc_owned_request_and_selected_route_untouched() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Rpc);
    let ticket = wire
        .send_rpc(
            &mut authority,
            meta,
            cap,
            19,
            Deadline::after(0, 5).unwrap(),
            0,
        )
        .unwrap();
    assert!(
        wire.expire_async(&mut authority, 10)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(wire.pending(), 1);
    assert_eq!(wire.accepted_senders().next().unwrap().0, ticket.0);
    let (mut authority, _scheduler, _meta, _cap, mut selected) = fixture(DeliveryMode::Selected);
    assert!(
        selected
            .expire_async(&mut authority, 10)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(selected.pending(), 0);
}

#[cfg(feature = "test-m6-session")]
#[test]
fn actual_wire_withdrawal_releases_accepted_bookkeeping_without_aliasing_new_ticket() {
    use crate::rpc::{MessageShape, Policy};
    use core::num::NonZeroU64;
    let (mut authority, mut scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Rpc);
    let callee = scheduler.create_thread(meta.process).unwrap();
    let mut rpc = Rpc::new(NonZeroU64::new(71).unwrap());
    for thread in [meta.thread, callee] {
        rpc.register_thread(&authority, &scheduler, thread, meta.job, meta.domain, None)
            .unwrap();
    }
    rpc.bind_endpoint(
        &authority,
        meta.domain,
        cap,
        callee,
        Policy::new(8, 0).unwrap(),
    )
    .unwrap();
    let deadline = Deadline::after(0, 5).unwrap();
    let id = rpc
        .begin(
            &authority,
            meta.thread,
            cap,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            0,
        )
        .unwrap();
    let ticket = wire
        .send_rpc(&mut authority, meta, cap, 19, deadline, 0)
        .unwrap();
    assert_eq!(scheduler.dispatch(0).unwrap().unwrap().thread, meta.thread);
    let wait = scheduler.block_guarded(0, deadline).unwrap();
    rpc.expire(5).unwrap();
    assert_eq!(scheduler.advance(5), Ok(0));
    assert_eq!(wire.accepted_senders().count(), 1);
    wire.withdraw_rpc(&mut authority, &mut rpc, callee, id, ticket, 5)
        .unwrap();
    assert_eq!(
        (
            wire.pending(),
            wire.accepted_senders().count(),
            rpc.outstanding()
        ),
        (0, 0, 0)
    );
    assert!(scheduler.waiting(wait));
    assert!(scheduler.wake(wait));
    let next = wire
        .send_rpc(
            &mut authority,
            meta,
            cap,
            29,
            Deadline::after(5, 5).unwrap(),
            5,
        )
        .unwrap();
    assert_ne!(next, ticket);
    assert!(
        wire.withdraw_rpc(&mut authority, &mut rpc, callee, id, ticket, 5)
            .is_err()
    );
    assert_eq!((wire.pending(), wire.accepted_senders().count()), (1, 1));
    let (delivery, _, _) = wire
        .receive_rpc(
            &mut authority,
            Metadata {
                thread: callee,
                ..meta
            },
            cap,
            5,
        )
        .unwrap();
    assert_eq!(delivery.ticket, next);
    assert_eq!(&delivery.bytes[..8], &29u64.to_le_bytes());
}

#[cfg(feature = "test-m6-session")]
#[test]
fn actual_receive_capture_reclaims_future_then_exactly_expired_scalar_without_delivery() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let expired_ticket = wire
        .send(
            &mut authority,
            meta,
            cap,
            71,
            Deadline::after(0, 5).unwrap(),
            0,
        )
        .unwrap();
    let live_ticket = wire
        .send(
            &mut authority,
            meta,
            cap,
            72,
            Deadline::after(0, 10).unwrap(),
            0,
        )
        .unwrap();
    // Executor observation precedes actual user resume. Its tick4 cleanup is
    // insufficient when the Receive syscall really returns at exact tick5.
    assert!(
        wire.expire_async(&mut authority, 4)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    let captured = wire.receive_async_at(&mut authority, meta, cap, 5).unwrap();
    assert!(captured.delivery.is_none());
    let receipts: std::vec::Vec<_> = captured.expired.into_iter().flatten().collect();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].message.ticket, expired_ticket);
    assert_eq!(receipts[0].message.bytes, 71u64.to_le_bytes());
    assert_eq!(
        wire.pending(),
        1,
        "later live message is still queued, not ACKed"
    );
    let captured = wire.receive_async_at(&mut authority, meta, cap, 5).unwrap();
    assert!(captured.expired.iter().all(Option::is_none));
    assert_eq!(captured.delivery.unwrap().0.ticket, live_ticket);
    assert_eq!(wire.pending(), 0);
    let next = wire
        .send(
            &mut authority,
            meta,
            cap,
            73,
            Deadline::after(5, 5).unwrap(),
            5,
        )
        .unwrap();
    assert!(next.0 > live_ticket.0);
    assert!(
        wire.expire_async(&mut authority, 5)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(wire.pending(), 1);
}

#[cfg(feature = "test-m6-session")]
#[test]
fn receive_expiry_requires_actual_receiver_and_never_consumes_rpc_or_selected_routes() {
    for mode in [
        DeliveryMode::Async,
        DeliveryMode::Rpc,
        DeliveryMode::Selected,
    ] {
        let (mut authority, _scheduler, meta, cap, mut wire) = fixture(mode);
        let ticket = match mode {
            DeliveryMode::Async => Some(
                wire.send(
                    &mut authority,
                    meta,
                    cap,
                    7,
                    Deadline::after(0, 5).unwrap(),
                    0,
                )
                .unwrap(),
            ),
            DeliveryMode::Rpc => Some(
                wire.send_rpc(
                    &mut authority,
                    meta,
                    cap,
                    7,
                    Deadline::after(0, 5).unwrap(),
                    0,
                )
                .unwrap(),
            ),
            DeliveryMode::Selected => None,
        };
        let other = authority.create_space().unwrap();
        let wrong = Metadata {
            domain: other,
            ..meta
        };
        assert!(
            wire.receive_async_at(&mut authority, wrong, cap, 5)
                .is_err()
        );
        assert_eq!(wire.pending(), usize::from(ticket.is_some()));
        if mode != DeliveryMode::Async {
            assert!(matches!(
                wire.receive_async_at(&mut authority, meta, cap, 5),
                Err(IpcError::RestrictedBinding)
            ));
            assert_eq!(wire.pending(), usize::from(ticket.is_some()));
        }
    }
}

#[cfg(feature = "test-m6-session")]
#[test]
fn expiry_preflight_skips_only_non_async_or_both_actual_empty_owners() {
    std::eprintln!(
        "actual_async_expiry_batch_bytes={}",
        core::mem::size_of::<[Option<wire::AsyncExpiry>; crate::ipc::MAX_MESSAGES]>()
    );
    for mode in [
        DeliveryMode::Rpc,
        DeliveryMode::Selected,
        DeliveryMode::Async,
    ] {
        let (mut authority, _scheduler, meta, cap, mut wire) = fixture(mode);
        assert!(!wire.needs_async_expiry());
        let ticket = wire
            .mailbox
            .as_mut()
            .unwrap()
            .send(
                &mut authority,
                meta.domain,
                cap,
                Outgoing {
                    bytes: b"queued01",
                    capability: None,
                    deadline: Deadline::after(0, 5).unwrap(),
                },
                0,
            )
            .unwrap();
        assert_eq!(wire.needs_async_expiry(), mode == DeliveryMode::Async);
        // A queued message without a transport row is still real ownership;
        // the preflight cannot hide it merely because accepted[] is empty.
        assert_eq!(wire.pending(), 1);
        assert_eq!(
            wire.mailbox
                .as_ref()
                .unwrap()
                .peek_ticket(&authority, meta.domain, cap, 0),
            Ok(ticket)
        );
    }
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let ticket = wire
        .send(
            &mut authority,
            meta,
            cap,
            1,
            Deadline::after(0, 5).unwrap(),
            0,
        )
        .unwrap();
    assert!(wire.needs_async_expiry());
    assert!(
        wire.expire_async(&mut authority, 4)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    let expired = wire.expire_async(&mut authority, 5).unwrap();
    assert_eq!(
        expired.iter().flatten().next().unwrap().message.ticket,
        ticket
    );
    assert_eq!(wire.pending(), 0);
    assert!(!wire.needs_async_expiry());
    wire.mailbox = None;
    assert!(
        wire.needs_async_expiry(),
        "no mailbox is not proof of an empty mailbox"
    );
}

#[cfg(feature = "test-m6-session")]
#[test]
fn expiry_preflight_preserves_live_ledger_only_and_capability_escrow_debt() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let ticket = wire
        .send(
            &mut authority,
            meta,
            cap,
            3,
            Deadline::after(0, 5).unwrap(),
            0,
        )
        .unwrap();
    // Deliberately bypass Wire's real delivery ledger update to model a broken
    // retained join. Empty mailbox alone cannot silently certify cleanup.
    assert_eq!(
        wire.mailbox
            .as_mut()
            .unwrap()
            .receive(&mut authority, meta.domain, cap, 0)
            .unwrap()
            .ticket,
        ticket
    );
    assert_eq!(wire.pending(), 0);
    assert!(wire.needs_async_expiry());
    assert!(matches!(
        wire.expire_async(&mut authority, 5),
        Err(IpcError::InvalidTicket)
    ));
    assert!(wire.needs_async_expiry());

    for mode in [DeliveryMode::Selected, DeliveryMode::Async] {
        let (mut authority, _scheduler, meta, cap, mut wire) = fixture(mode);
        let memory = authority
            .create_root(meta.domain, Kind::Memory, Rights::READ | Rights::TRANSFER)
            .unwrap();
        wire.mailbox
            .as_mut()
            .unwrap()
            .send(
                &mut authority,
                meta.domain,
                cap,
                Outgoing {
                    bytes: b"withcap1",
                    capability: Some(memory),
                    deadline: Deadline::after(0, 5).unwrap(),
                },
                0,
            )
            .unwrap();
        assert_eq!(wire.needs_async_expiry(), mode == DeliveryMode::Async);
        assert!(
            wire.expire_async(&mut authority, 5)
                .unwrap()
                .iter()
                .all(Option::is_none)
        );
        assert_eq!(
            wire.pending(),
            1,
            "no cap/Selected credit is cleared by scalar maintenance"
        );
        assert!(
            authority
                .authorize(meta.domain, memory, Kind::Memory, Rights::READ)
                .is_err()
        );
    }
}

/// Prove the canonical queue property that permits the executor's repeated-
/// tick maintenance memo. Accepted work introduced after that tick's sweep
/// cannot already be expired; actual RECEIVE still checks a later capture.
#[cfg(feature = "test-m6-session")]
#[test]
fn same_tick_send_cannot_create_due_debt_and_later_receive_reclaims_exact_credit() {
    let (mut authority, _scheduler, meta, cap, mut wire) = fixture(DeliveryMode::Async);
    let old = wire
        .send(
            &mut authority,
            meta,
            cap,
            1,
            Deadline::after(0, 5).unwrap(),
            0,
        )
        .unwrap();
    let expired = wire.expire_async(&mut authority, 5).unwrap();
    assert_eq!(expired.iter().flatten().next().unwrap().message.ticket, old);
    assert_eq!(wire.pending(), 0);
    // A same-tick insertion at/before the already completed sweep is refused
    // without consuming either mailbox capacity or the accepted ledger.
    for cut in [4, 5] {
        assert_eq!(
            wire.send(
                &mut authority,
                meta,
                cap,
                2,
                Deadline::after(0, cut).unwrap(),
                5
            ),
            Err(IpcError::Expired)
        );
        assert_eq!(wire.pending(), 0);
        assert!(!wire.needs_async_expiry());
    }
    let new = wire
        .send(
            &mut authority,
            meta,
            cap,
            3,
            Deadline::after(5, 1).unwrap(),
            5,
        )
        .unwrap();
    assert_ne!(old, new);
    assert!(
        wire.expire_async(&mut authority, 5)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(wire.pending(), 1);
    // User execution may cross the cut before the next executor sweep. The
    // real receiver boundary must release only this never-delivered ticket.
    let received = wire.receive_async_at(&mut authority, meta, cap, 6).unwrap();
    assert!(received.delivery.is_none());
    let receipt = received.expired.iter().flatten().next().unwrap();
    assert_eq!(receipt.message.ticket, new);
    assert_eq!(receipt.message.deadline.tick(), 6);
    assert_eq!(wire.pending(), 0);
    assert!(!wire.needs_async_expiry());
    // The canonical queue has observed 6. A regressed capture is not converted
    // into cached success, and cannot introduce a replacement message.
    assert_eq!(
        wire.send(
            &mut authority,
            meta,
            cap,
            4,
            Deadline::after(5, 2).unwrap(),
            5
        ),
        Err(IpcError::ClockReversed)
    );
    assert_eq!(wire.pending(), 0);
}
