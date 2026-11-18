use crate::{Deadline, Domain, Error, entropy, freshness};

fn domain(value: u64) -> Domain {
    Domain::new(value).unwrap()
}

fn qualified(start: u64, through: u64, earliest: u64, latest: u64) -> freshness::Time {
    freshness::Time::Qualified(
        freshness::QualifiedWindow::new(
            domain(1).at(start),
            domain(1).at(through),
            freshness::UtcInterval::new(earliest, latest).unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn boot_domains_and_checked_deadlines_cannot_be_interchanged() {
    assert_eq!(Domain::new(0), Err(Error::InvalidDomain));
    let start = domain(1).at(10);
    let deadline = Deadline::after(start, 8).unwrap();
    assert_eq!(deadline.reached(domain(1).at(17)), Ok(false));
    assert_eq!(deadline.reached(domain(1).at(18)), Ok(true));
    assert_eq!(
        deadline.reached(domain(1).at(9)),
        Err(Error::ClockRegression)
    );
    assert_eq!(
        deadline.reached(domain(2).at(18)),
        Err(Error::DifferentBoot)
    );
    assert_eq!(
        Deadline::after(domain(1).at(u64::MAX), 1),
        Err(Error::Overflow)
    );
    assert_eq!(Deadline::after(start, 0).unwrap().reached(start), Ok(true));
}

#[test]
fn unknown_or_unauthenticated_wall_time_never_approves_new_metadata() {
    let validity = freshness::Validity::new(100, 200).unwrap();
    assert_eq!(
        freshness::check(freshness::Time::Unknown, validity, domain(1).at(0), 0),
        Err(freshness::Error::UnknownTime)
    );
    // An accurate-looking RTC/NTP value is still not authenticated time.
    let tentative = freshness::Time::Tentative(freshness::UtcInterval::new(150, 150).unwrap());
    assert_eq!(
        freshness::check(tentative, validity, domain(1).at(0), 0),
        Err(freshness::Error::UnqualifiedTime)
    );
}

#[test]
fn every_possible_time_must_be_inside_the_metadata_validity_interval() {
    let validity = freshness::Validity::new(100, 200).unwrap();
    let now = domain(1).at(5);
    assert_eq!(
        freshness::check(qualified(5, 5, 100, 199), validity, now, 90),
        Ok(freshness::Decision { next_floor: 100 })
    );
    for (earliest, latest, expected) in [
        (90, 99, freshness::Error::NotYetValid),
        (200, 201, freshness::Error::Expired),
        (99, 100, freshness::Error::Uncertain),
        (199, 200, freshness::Error::Uncertain),
        (0, u64::MAX, freshness::Error::Uncertain),
    ] {
        assert_eq!(
            freshness::check(qualified(5, 5, earliest, latest), validity, now, 0),
            Err(expected)
        );
    }
}

#[test]
fn old_samples_cannot_gain_an_arbitrary_retry_age_allowance() {
    let validity = freshness::Validity::new(100, 200).unwrap();
    let time = qualified(10, 12, 150, 153);
    assert!(freshness::check(time, validity, domain(1).at(12), 0).is_ok());
    assert_eq!(
        freshness::check(time, validity, domain(1).at(13), 0),
        Err(freshness::Error::StaleSample)
    );
    assert_eq!(
        freshness::check(time, validity, domain(1).at(9), 0),
        Err(freshness::Error::Clock(Error::ClockRegression))
    );
    assert_eq!(
        freshness::check(time, validity, domain(2).at(10), 0),
        Err(freshness::Error::Clock(Error::DifferentBoot))
    );
}

#[test]
fn cold_floor_refuses_clock_rollback_without_claiming_disk_rollback_resistance() {
    let validity = freshness::Validity::new(100, 200).unwrap();
    let now = domain(1).at(5);
    // A persisted lower bound rejects even partially earlier possible UTC.
    assert_eq!(
        freshness::check(qualified(5, 5, 149, 151), validity, now, 150),
        Err(freshness::Error::Rollback)
    );
    assert_eq!(
        freshness::check(qualified(5, 5, 150, 151), validity, now, 150),
        Ok(freshness::Decision { next_floor: 150 })
    );
    assert_eq!(
        freshness::check(qualified(5, 5, 155, 159), validity, now, 150),
        Ok(freshness::Decision { next_floor: 155 })
    );
}

#[test]
fn invalid_time_ranges_fail_without_arithmetic_wrap() {
    assert_eq!(
        freshness::UtcInterval::new(2, 1),
        Err(freshness::Error::InvalidInterval)
    );
    assert_eq!(
        freshness::Validity::new(2, 2),
        Err(freshness::Error::InvalidInterval)
    );
    assert_eq!(
        freshness::Validity::new(3, 2),
        Err(freshness::Error::InvalidInterval)
    );
    let utc = freshness::UtcInterval::new(0, u64::MAX).unwrap();
    assert!(matches!(
        freshness::QualifiedWindow::new(domain(1).at(10), domain(1).at(9), utc),
        Err(freshness::Error::Clock(Error::ClockRegression))
    ));
    assert!(matches!(
        freshness::QualifiedWindow::new(domain(1).at(10), domain(2).at(11), utc),
        Err(freshness::Error::Clock(Error::DifferentBoot))
    ));
}

#[test]
fn entropy_starts_unavailable_and_cold_reopening_does_not_restore_readiness() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    assert_eq!(
        budget.reserve(domain(1).at(0), 32),
        Err(entropy::Error::Unavailable)
    );
    budget.reseeded(domain(1).at(1), 1, 1024, 10).unwrap();
    assert_eq!(budget.reserve(domain(1).at(1), 32), Ok(1));
    let mut cold = entropy::Budget::unavailable(domain(2));
    assert_eq!(
        cold.reserve(domain(2).at(0), 32),
        Err(entropy::Error::Unavailable)
    );
    assert_eq!(
        cold.reseeded(domain(1).at(1), 2, 1024, 10),
        Err(entropy::Error::Clock(Error::DifferentBoot))
    );
}

#[test]
fn output_budget_is_consumed_even_if_delivery_would_fail() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    budget.reseeded(domain(1).at(1), 1, 64, 10).unwrap();
    assert_eq!(budget.reserve(domain(1).at(1), 32), Ok(1));
    // Simulated transport failure: there is no refund/regeneration API.
    assert_eq!(budget.reserve(domain(1).at(1), 32), Ok(1));
    assert_eq!(
        budget.reserve(domain(1).at(1), 1),
        Err(entropy::Error::ReseedRequired)
    );
    assert_eq!(
        budget.reserve(domain(1).at(1), 1),
        Err(entropy::Error::Unavailable)
    );
    assert_eq!(
        budget.reseeded(domain(1).at(2), 1, 64, 10),
        Err(entropy::Error::StaleGeneration)
    );
    budget.reseeded(domain(1).at(2), 2, 64, 10).unwrap();
    assert_eq!(budget.reserve(domain(1).at(2), 1), Ok(2));
}

#[test]
fn invalid_entropy_requests_do_not_consume_valid_output() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    budget.reseeded(domain(1).at(1), 1, 32, 10).unwrap();
    for bytes in [0, 4097, u64::MAX] {
        assert_eq!(
            budget.reserve(domain(1).at(1), bytes),
            Err(entropy::Error::InvalidRequest)
        );
    }
    assert_eq!(budget.reserve(domain(1).at(1), 32), Ok(1));
}

#[test]
fn malformed_output_request_cannot_hide_observed_clock_rollback() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    budget.reseeded(domain(1).at(1), 1, 32, 1000).unwrap();
    assert_eq!(
        budget.reserve(domain(1).at(100), 0),
        Err(entropy::Error::InvalidRequest)
    );
    assert_eq!(
        budget.reserve(domain(1).at(99), 1),
        Err(entropy::Error::Clock(Error::ClockRegression))
    );
    assert_eq!(
        budget.reserve(domain(1).at(101), 1),
        Err(entropy::Error::Unavailable)
    );
}

#[test]
fn stale_entropy_time_and_generation_fail_closed() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    budget.reseeded(domain(1).at(1), 1, 1024, 3).unwrap();
    assert_eq!(
        budget.reserve(domain(1).at(4), 1),
        Err(entropy::Error::ReseedRequired)
    );
    assert_eq!(
        budget.reserve(domain(1).at(4), 1),
        Err(entropy::Error::Unavailable)
    );
    budget.reseeded(domain(1).at(5), 2, 1024, 10).unwrap();
    assert_eq!(budget.reserve(domain(1).at(7), 1), Ok(2));
    assert_eq!(
        budget.reserve(domain(1).at(6), 1),
        Err(entropy::Error::Clock(Error::ClockRegression))
    );
    assert_eq!(
        budget.reserve(domain(1).at(8), 1),
        Err(entropy::Error::Unavailable)
    );
}

#[test]
fn refused_reseed_still_records_the_actual_clock_high_water() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    budget.reseeded(domain(1).at(1), 1, 32, 1000).unwrap();
    assert_eq!(
        budget.reseeded(domain(1).at(100), 1, 32, 1000),
        Err(entropy::Error::StaleGeneration)
    );
    assert_eq!(
        budget.reserve(domain(1).at(6), 1),
        Err(entropy::Error::Clock(Error::ClockRegression))
    );
    assert_eq!(
        budget.reserve(domain(1).at(101), 1),
        Err(entropy::Error::Unavailable)
    );
    budget.reseeded(domain(1).at(102), 2, 32, 1000).unwrap();
    assert_eq!(
        budget.reseeded(domain(1).at(103), 3, 0, 1000),
        Err(entropy::Error::InvalidRequest)
    );
    assert_eq!(budget.reserve(domain(1).at(104), 32), Ok(2));
}

#[test]
fn failed_source_is_explicit_and_reseed_cannot_wrap_or_go_backwards() {
    let mut budget = entropy::Budget::unavailable(domain(1));
    budget.reseeded(domain(1).at(1), u64::MAX, 32, 10).unwrap();
    budget.fail();
    assert_eq!(
        budget.reserve(domain(1).at(1), 1),
        Err(entropy::Error::Unavailable)
    );
    for generation in [0, 1, u64::MAX] {
        assert_eq!(
            budget.reseeded(domain(1).at(2), generation, 32, 10),
            Err(entropy::Error::StaleGeneration)
        );
    }
    let mut overflow = entropy::Budget::unavailable(domain(1));
    assert_eq!(
        overflow.reseeded(domain(1).at(u64::MAX), 1, 32, 1),
        Err(entropy::Error::Clock(Error::Overflow))
    );
    assert_eq!(
        overflow.reserve(domain(1).at(u64::MAX), 1),
        Err(entropy::Error::Unavailable)
    );
}
