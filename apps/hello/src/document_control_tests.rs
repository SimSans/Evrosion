use super::*;
use ev_userspace_contract::document::Choice;

#[test]
fn publication_owns_frame_until_the_matching_actual_reply() {
    let mut c = Client::new();
    let r = c.publish(10, 20).unwrap();
    assert!(!c.frame_available());
    assert_eq!(c.open(Access::Edit), Err(Error::Busy));
    assert_eq!(c.publish(11, 30), Err(Error::Busy));
    assert_eq!(
        c.reply(&r.reply(Outcome::Published).encode(), 0, 12),
        Ok(Completion::Published { late: false })
    );
    assert!(c.frame_available());
    assert!(!c.busy());
    let next = c.publish(13, 30).unwrap();
    assert_eq!(next.nonce(), r.nonce() + 1);
}

#[test]
fn timeout_keeps_the_frame_and_only_exact_late_completion_releases_it() {
    let mut c = Client::new();
    let r = c.publish(10, 20).unwrap();
    assert_eq!(c.poll(20), Err(Error::Deadline));
    assert!(!c.frame_available());
    assert_eq!(c.publish(21, 40), Err(Error::Uncertain));
    let wrong = Request::new(Operation::Publish, r.nonce() + 1).unwrap();
    assert_eq!(
        c.reply(&wrong.reply(Outcome::Published).encode(), 0, 21),
        Err(Error::Mismatch)
    );
    assert!(!c.frame_available());
    assert_eq!(c.pending_request(), Some(r));
    assert_eq!(
        c.reply(&r.reply(Outcome::Published).encode(), 0, 22),
        Ok(Completion::Published { late: true })
    );
    assert!(c.frame_available());
    assert!(!c.busy());
    assert_eq!(
        c.reply(&r.reply(Outcome::Published).encode(), 0, 23),
        Err(Error::Unsolicited)
    );
}

#[test]
fn malformed_or_wrong_capability_ack_cannot_release_the_frame() {
    for case in 0..4 {
        let mut c = Client::new();
        let r = c.publish(10, 20).unwrap();
        let mut bytes = r.reply(Outcome::Published).encode();
        let caps = if case == 3 { 1 } else { 0 };
        match case {
            0 => bytes[0] = 0,
            1 => bytes[2] = 2,
            2 => bytes[3] = 99,
            _ => (),
        }
        assert_eq!(c.reply(&bytes, caps, 11), Err(Error::Protocol));
        assert!(!c.frame_available());
        assert_eq!(c.pending_request(), Some(r));
        assert_eq!(c.poll(12), Err(Error::Uncertain));
    }
}

#[test]
fn open_wait_is_bounded_nonblocking_ui_state_and_never_a_shared_frame_loan() {
    let mut c = Client::new();
    let r = c.open(Access::Edit).unwrap();
    assert!(c.frame_available());
    assert_eq!(c.poll(u64::MAX), Ok(()));
    assert_eq!(c.publish(11, 20), Err(Error::Busy));
    let grant = Granted::new(r.nonce(), Choice::Private, Access::Edit).unwrap();
    assert_eq!(c.grant(&grant.encode(), 1), Ok(grant));
    assert!(!c.busy());
    let r = c.open(Access::Read).unwrap();
    assert_eq!(
        c.reply(&r.reply(Outcome::Cancelled).encode(), 0, 12),
        Ok(Completion::Refused {
            outcome: Outcome::Cancelled,
            late: false
        })
    );
    assert!(!c.busy());
    assert!(c.frame_available());
}

#[test]
fn read_request_cannot_accept_edit_grant_and_published_ack_cannot_complete_open() {
    let mut c = Client::new();
    let r = c.open(Access::Read).unwrap();
    let grant = Granted::new(r.nonce(), Choice::Notes, Access::Edit).unwrap();
    assert_eq!(c.grant(&grant.encode(), 1), Err(Error::Mismatch));
    assert!(c.busy());
    assert_eq!(
        c.reply(&r.reply(Outcome::Published).encode(), 0, 10),
        Err(Error::Protocol)
    );
    assert!(c.busy());
    let correct = Granted::new(r.nonce(), Choice::Notes, Access::Read).unwrap();
    assert_eq!(c.grant(&correct.encode(), 1), Ok(correct));
    assert!(!c.busy());
}

#[test]
fn old_nonce_cannot_release_a_new_publication_and_nonce_never_wraps() {
    let mut c = Client::new();
    let old = c.publish(1, 10).unwrap();
    c.reply(&old.reply(Outcome::Published).encode(), 0, 2)
        .unwrap();
    let new = c.publish(3, 20).unwrap();
    assert_eq!(
        c.reply(&old.reply(Outcome::Published).encode(), 0, 4),
        Err(Error::Mismatch)
    );
    assert_eq!(c.pending_request(), Some(new));
    assert!(!c.frame_available());
    c.reply(&new.reply(Outcome::Busy).encode(), 0, 5).unwrap();
    assert!(c.frame_available());
    c.sequence = u32::MAX - 1;
    assert_eq!(c.open(Access::Edit), Err(Error::Exhausted));
    assert!(!c.busy());
    assert_eq!(c.publish(7, 7), Err(Error::Deadline));
    assert_eq!(c.publish(7, u64::MAX), Err(Error::Deadline));
}
