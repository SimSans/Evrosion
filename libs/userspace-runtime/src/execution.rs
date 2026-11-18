// SPDX-License-Identifier: Apache-2.0
//! Internal process-runtime duration metadata. This does not grant CPU, extend
//! a Job budget or authorize a protected operation. The captured Kernel profile
//! owns renewable CPU accounting; services still bound each accepted operation.

/// Startup value reserved by the separately measured sustained-session profile.
/// Existing finite profiles continue to pass a nonzero absolute lifetime bound.
pub const SESSION: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    SessionNotAllowed,
    Expired,
    InvalidClock,
    InvalidSpan,
    Overflow,
}

/// Validate a captured startup duration before constructing any service owner.
/// `allow_session` belongs to the measured component's declared build profile.
pub fn validate(bound: u64, now: u64, allow_session: bool) -> Result<(), Error> {
    if now == u64::MAX || bound == u64::MAX {
        return Err(Error::InvalidClock);
    }
    if bound == SESSION {
        return if allow_session {
            Ok(())
        } else {
            Err(Error::SessionNotAllowed)
        };
    }
    if now >= bound {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}

/// A session has no automatic lifetime exit. Its execution remains subject to
/// independently enforced finite per-window CPU and per-operation resource caps.
pub fn live(bound: u64, now: u64) -> bool {
    now != u64::MAX && bound != u64::MAX && (bound == SESSION || now < bound)
}

/// Existing conformance fixtures retain their exact absolute operation horizon.
/// A session instead starts a fresh finite operation horizon at captured `now`.
/// Call once per operation and retain the result through retries; calling this
/// on each retry would incorrectly extend an already accepted operation.
pub fn deadline(bound: u64, now: u64, span: u64) -> Result<u64, Error> {
    if span == 0 || span == u64::MAX {
        return Err(Error::InvalidSpan);
    }
    if !live(bound, now) {
        return Err(if now == u64::MAX || bound == u64::MAX {
            Error::InvalidClock
        } else {
            Error::Expired
        });
    }
    let origin = if bound == SESSION { now } else { bound };
    origin
        .checked_add(span)
        .filter(|d| *d != u64::MAX)
        .ok_or(Error::Overflow)
}

/// Validate an inherited operation deadline at the recipient boundary. A
/// sustained recipient never accepts an infinite or arbitrarily distant wait.
pub fn accepts_deadline(bound: u64, now: u64, deadline: u64, max_span: u64) -> bool {
    if max_span == 0 || max_span == u64::MAX || !live(bound, now) || deadline == u64::MAX {
        return false;
    }
    let origin = if bound == SESSION { now } else { bound };
    origin
        .checked_add(max_span)
        .is_some_and(|end| deadline > origin && deadline <= end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_startup_and_operation_horizons_keep_their_original_semantics() {
        assert_eq!(validate(100, 40, false), Ok(()));
        assert_eq!(deadline(100, 40, 512), Ok(612));
        assert_eq!(deadline(100, 99, 512), Ok(612));
        assert_eq!(validate(100, 100, true), Err(Error::Expired));
        assert!(!live(100, 100));
        assert_eq!(deadline(100, 100, 512), Err(Error::Expired));
    }

    #[test]
    fn session_profile_requires_explicit_startup_selection_and_bounded_operations() {
        assert_eq!(validate(SESSION, 4, false), Err(Error::SessionNotAllowed));
        assert_eq!(validate(SESSION, 4, true), Ok(()));
        for now in [0, 5, 262_145, 1_000_000] {
            assert!(live(SESSION, now));
            assert_eq!(deadline(SESSION, now, 512), Ok(now + 512));
        }
    }

    #[test]
    fn invalid_time_empty_spans_and_unrepresentable_deadlines_fail_closed() {
        assert_eq!(validate(u64::MAX, 0, true), Err(Error::InvalidClock));
        assert_eq!(validate(SESSION, u64::MAX, true), Err(Error::InvalidClock));
        assert!(!live(SESSION, u64::MAX));
        assert_eq!(deadline(SESSION, 10, 0), Err(Error::InvalidSpan));
        assert_eq!(deadline(SESSION, 10, u64::MAX), Err(Error::InvalidSpan));
        assert_eq!(deadline(SESSION, u64::MAX - 2, 2), Err(Error::Overflow));
        assert_eq!(deadline(SESSION, u64::MAX - 2, 3), Err(Error::Overflow));
        assert_eq!(deadline(u64::MAX - 3, 1, 3), Err(Error::Overflow));
    }

    #[test]
    fn inherited_session_deadlines_refuse_expired_or_distant_operations() {
        assert!(accepts_deadline(SESSION, 1000, 1512, 1024));
        assert!(!accepts_deadline(SESSION, 1000, 1000, 1024));
        assert!(!accepts_deadline(SESSION, 1000, 2025, 1024));
        assert!(!accepts_deadline(SESSION, 1000, u64::MAX, 1024));
        assert!(!accepts_deadline(
            SESSION,
            u64::MAX - 512,
            u64::MAX - 1,
            1024
        ));
        assert!(accepts_deadline(100, 50, 612, 1024));
        assert!(!accepts_deadline(100, 50, 100, 1024));
        assert!(!accepts_deadline(100, 100, 612, 1024));
    }
}
