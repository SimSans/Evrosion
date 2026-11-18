//! Exercise the exact native captured-origin comparison, without executing a
//! syscall or claiming that model numbers establish actual Root authority.
//! The dedicated role16 capability and ServingOrigin capture remain native
//! prerequisites; packet metadata cannot construct those Kernel facts.
fn now() -> u64 {
    100
}
fn require(ok: bool, _code: u64) {
    assert!(ok);
}
#[allow(dead_code)]
#[path = "native/origin.rs"]
mod origin;
use origin::{Origin, RootSession};

fn captured() -> Origin {
    Origin {
        process: 1,
        thread: 2,
        registered: 3,
        epoch: 4,
        serial: 5,
        endpoint: 6,
        deadline: 200,
        status: 0,
    }
}
#[test]
fn pinned_native_root_session_refuses_foreign_identity_endpoint_epoch_or_incarnation() {
    let first = captured();
    let session = RootSession::new(first);
    assert!(first.live());
    assert!(session.matches(first));
    for other in [
        Origin {
            process: 9,
            ..first
        },
        Origin { thread: 9, ..first },
        Origin {
            registered: 9,
            ..first
        },
        Origin {
            endpoint: 9,
            ..first
        },
        Origin { epoch: 9, ..first },
    ] {
        assert!(!session.matches(other));
    }
    // New distinct calls may use new serials/cuts, under the same captured
    // service session. Replay cache + per-call capture retain exact correlation.
    let next = Origin {
        serial: 7,
        deadline: 201,
        ..first
    };
    assert!(session.matches(next));
    assert!(!first.same_call(next));
    assert!(!Origin { status: 1, ..first }.live());
    assert!(
        !Origin {
            deadline: 100,
            ..first
        }
        .live()
    );
    assert!(
        !Origin {
            deadline: u64::MAX,
            ..first
        }
        .live()
    );
    assert!(
        !Origin {
            deadline: 8293,
            ..first
        }
        .live()
    );
}
