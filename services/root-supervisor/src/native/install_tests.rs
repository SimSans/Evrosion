//! Exact State -> Backend -> Store checks. Injected outside writes deliberately
//! violate the owned-disk/exclusive-writer scope; they must never erase foreign
//! contents, and partial formatting is not a cross-volume atomic transaction.
use super::*;

fn app_regions(bytes: &[Sector]) -> Vec<Sector> {
    bytes[64..78]
        .iter()
        .chain(&bytes[80..94])
        .copied()
        .collect()
}

#[test]
fn cold_blank_observation_is_required_and_each_store_still_checks_its_region() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let media = disk();
    let mut owner = state(media.clone());
    assert_eq!(owner.install(&packages, DEADLINE), Err(Error::State));
    assert!(media.borrow().calls.is_empty());
    owner.open(&packages, DEADLINE).unwrap();
    assert!(owner.blank && owner.record.is_none() && owner.session.is_none());
    let observed = media.borrow().cache.clone();
    media.borrow_mut().calls.clear();
    owner.install(&packages, DEADLINE).unwrap();
    let m = media.borrow();
    // The first real format still checks ALL AppData sectors, rather than
    // repeating the already completed both-region scan from cold open.
    assert_eq!(
        &m.calls[..14],
        &core::array::from_fn::<_, 14, _>(|local| block::Request::Read {
            sector: Region::AppData.wire_start() + local as u32,
        })
    );
    for local in 0..14 {
        assert!(m.calls.contains(&block::Request::Read {
            sector: Region::AppRegistry.wire_start() + local,
        }));
    }
    assert_eq!(&m.cache[..64], &observed[..64]);
    assert_eq!(&m.cache[78..80], &observed[78..80]);
    assert_eq!(&m.cache[94..], &observed[94..]);
    let calls = m.calls.clone();
    drop(m);
    assert!(!owner.blank);
    assert_eq!(owner.install(&packages, DEADLINE), Err(Error::State));
    assert_eq!(media.borrow().calls, calls);
    drop(owner);
    cold(&media);
    let mut reopened = state(media);
    reopened.open(&packages, DEADLINE).unwrap();
    assert_eq!(reopened.data().unwrap().value(), 1001);
}

#[test]
fn every_nonblank_cold_region_refuses_without_formatting_or_erasing_content() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    for first in [64, 80] {
        for local in 0..14 {
            let media = disk();
            {
                let mut m = media.borrow_mut();
                m.cache[first + local][71] = 0x57;
                m.durable = m.cache.clone();
            }
            let before = media.borrow().cache.clone();
            let mut owner = state(media.clone());
            assert!(owner.open(&packages, DEADLINE).is_err());
            assert!(owner.recovery_required());
            assert!(!owner.blank);
            let calls = media.borrow().calls.clone();
            assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Recovery));
            let m = media.borrow();
            assert_eq!(m.cache, before);
            assert_eq!(m.durable, before);
            assert!(m.writes.is_empty());
            assert_eq!(m.calls, calls, "failed observation cannot authorize format");
        }
    }
}

#[test]
fn failed_cold_read_never_creates_blank_credit_or_retries_after_failure() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let media = disk();
    media.borrow_mut().fail_next = true;
    let before = media.borrow().cache.clone();
    let mut owner = state(media.clone());
    assert!(owner.open(&packages, DEADLINE).is_err());
    assert!(!owner.blank && owner.recovery_required());
    let calls = media.borrow().calls.clone();
    assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Recovery));
    assert_eq!(owner.open(&packages, DEADLINE), Err(Error::Recovery));
    let m = media.borrow();
    assert_eq!(m.calls, calls);
    assert!(m.writes.is_empty());
    assert_eq!(m.cache, before);
}

#[test]
fn outside_mutation_after_observation_cannot_bypass_either_store_blank_check() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    for first in [64, 80] {
        for local in 0..14 {
            let media = disk();
            let mut owner = state(media.clone());
            owner.open(&packages, DEADLINE).unwrap();
            // Not a permitted concurrent writer in the actual profile. Keep
            // this adversarial defense test distinct from freshness claims.
            {
                let mut m = media.borrow_mut();
                m.cache[first + local][91] = 0x4d;
                m.durable = m.cache.clone();
                m.writes.clear();
            }
            let foreign = media.borrow().cache[first..first + 14].to_vec();
            assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Storage));
            assert!(owner.recovery_required());
            let m = media.borrow();
            assert_eq!(&m.cache[first..first + 14], foreign);
            assert_eq!(&m.durable[first..first + 14], foreign);
            assert!(
                m.writes
                    .iter()
                    .all(|sector| !(first..first + 14).contains(sector))
            );
            let calls = m.calls.clone();
            let bytes = m.cache.clone();
            drop(m);
            assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Recovery));
            assert_eq!(media.borrow().calls, calls);
            assert_eq!(media.borrow().cache, bytes);
        }
    }
}

#[test]
fn accepted_install_write_or_flush_with_unknown_reply_fences_every_retry() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    for lose_flush in [false, true] {
        let media = disk();
        let mut owner = state(media.clone());
        owner.open(&packages, DEADLINE).unwrap();
        if lose_flush {
            media.borrow_mut().lose_flush_reply = true;
        } else {
            media.borrow_mut().lose_write_reply = true;
        }
        assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Storage));
        assert!(owner.recovery_required() && owner.backend.poisoned());
        let m = media.borrow();
        assert!(
            !m.writes.is_empty(),
            "fault must occur after an accepted mutation"
        );
        let calls = m.calls.clone();
        let bytes = m.cache.clone();
        drop(m);
        assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Recovery));
        assert_eq!(owner.open(&packages, DEADLINE), Err(Error::Recovery));
        assert_eq!(media.borrow().calls, calls);
        assert_eq!(media.borrow().cache, bytes);
    }
}

#[test]
fn no_session_can_write_app_data_while_disjoint_system_and_grant_regions_are_used() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let media = composed_disk();
    let mut owner = state(media.clone());
    owner.open(&packages, DEADLINE).unwrap();
    let before = app_regions(&media.borrow().cache);
    let calls = media.borrow().calls.clone();
    assert_eq!(owner.admit(&packages, Slot::A, WHO), Err(Error::State));
    for request in [DataRequest::Read, DataRequest::SetValue(2026)] {
        assert_eq!(
            owner.data_request(&packages, WHO, request, DEADLINE),
            Response::Refused(Refusal::Denied)
        );
    }
    assert_eq!(
        owner.prepare(&packages, Change::Activate, DEADLINE),
        Err(Error::State)
    );
    assert_eq!(media.borrow().calls, calls);
    owner.system_initialize(&packages, DEADLINE).unwrap();
    owner
        .grant_initialize(&packages, grant_user(), DEADLINE)
        .unwrap();
    assert_eq!(app_regions(&media.borrow().cache), before);
    assert!(owner.blank && owner.session.is_none() && owner.pending.is_none());
    owner.install(&packages, DEADLINE).unwrap();
}
