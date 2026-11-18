//! Real State/Registry/Store operations exercise the same decision helper used
//! by the controller. Actual held-process admission remains a separate VM gate.
use super::*;
#[test]
fn first_bundled_launch_prepares_activation_and_cold_active_launch_never_reinstalls() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let media = disk();
    let mut owner = state(media.clone());
    assert_eq!(owner.bundled_launch(&packages), Err(Error::State));
    owner.open(&packages, DEADLINE).unwrap();
    assert_eq!(owner.bundled_launch(&packages), Ok(BundledLaunch::Install));
    media.borrow_mut().calls.clear();
    owner.install(&packages, DEADLINE).unwrap();
    {
        let m = media.borrow();
        let reads = m
            .calls
            .iter()
            .filter(|r| matches!(r, block::Request::Read { .. }))
            .count();
        let writes = m
            .calls
            .iter()
            .filter(|r| matches!(r, block::Request::Write { .. }))
            .count();
        let flushes = m
            .calls
            .iter()
            .filter(|r| matches!(r, block::Request::Flush))
            .count();
        std::eprintln!(
            "model_install_calls={} reads={reads} writes={writes} flushes={flushes}",
            m.calls.len()
        );
        std::eprintln!("model_first_data_stage={:?}", &m.calls[..23]);
    }
    assert_eq!(
        owner.bundled_launch(&packages),
        Ok(BundledLaunch::ActivateA)
    );
    assert_eq!(owner.active(&packages), Ok(None));
    assert_eq!(
        owner.prepare(&packages, Change::Activate, DEADLINE),
        Ok(Some(Slot::A))
    );
    assert_eq!(
        owner.active(&packages),
        Ok(None),
        "a prepared activation is not active or dispatched"
    );
    assert_eq!(owner.bundled_launch(&packages), Err(Error::State));
    owner.commit(&packages, DEADLINE).unwrap();
    assert_eq!(
        owner.bundled_launch(&packages),
        Ok(BundledLaunch::Start(Slot::A))
    );
    assert_eq!(owner.record().unwrap().revision(), 2);
    drop(owner);
    cold(&media);
    media.borrow_mut().writes.clear();
    let mut reopened = state(media.clone());
    reopened.open(&packages, DEADLINE).unwrap();
    assert_eq!(
        reopened.bundled_launch(&packages),
        Ok(BundledLaunch::Start(Slot::A))
    );
    assert_eq!(reopened.record().unwrap().revision(), 2);
    assert_eq!(reopened.data().unwrap().value(), 1001);
    assert!(
        media.borrow().writes.is_empty(),
        "cold launch never reformats or republishes an active namespace"
    );
}
#[test]
fn explicit_removal_is_not_implicit_permission_to_format_on_bundled_launch() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let media = disk();
    let mut owner = state(media.clone());
    owner.open(&packages, DEADLINE).unwrap();
    owner.install(&packages, DEADLINE).unwrap();
    owner
        .prepare(&packages, Change::Activate, DEADLINE)
        .unwrap();
    owner.commit(&packages, DEADLINE).unwrap();
    owner.prepare(&packages, Change::Remove, DEADLINE).unwrap();
    owner.commit(&packages, DEADLINE).unwrap();
    let calls = media.borrow().calls.clone();
    assert_eq!(owner.bundled_launch(&packages), Err(Error::State));
    assert_eq!(media.borrow().calls, calls);
    assert_eq!(owner.data().unwrap().value(), 1001);
}
#[test]
fn unknown_install_completion_fences_gui_retry_before_any_new_storage_work() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let media = disk();
    let mut owner = state(media.clone());
    owner.open(&packages, DEADLINE).unwrap();
    media.borrow_mut().lose_write_reply = true;
    assert_eq!(owner.install(&packages, DEADLINE), Err(Error::Storage));
    let calls = media.borrow().calls.clone();
    assert_eq!(owner.bundled_launch(&packages), Err(Error::Recovery));
    assert_eq!(media.borrow().calls, calls);
}
