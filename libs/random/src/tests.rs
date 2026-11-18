use super::*;

fn domain() -> Domain {
    Domain::new(7).unwrap()
}
fn seeded() -> Generator {
    let mut generator = Generator::unavailable(domain());
    let mut seed = [0x19; 32]; // Deterministic TEST material, never source evidence.
    generator
        .reseed_after_authorized_source(domain().at(1), 1, &mut seed)
        .unwrap();
    assert_eq!(seed, [0; 32]);
    generator
}

#[test]
fn selected_twenty_round_engine_matches_the_published_zero_input_vector() {
    // ChaCha20 reference block for zero key, stream/nonce0 and block counter0.
    // This checks algorithm/backend selection, never entropy qualification.
    let mut engine = ChaCha20Rng::from_seed([0; 32]);
    let mut block = [0; 32];
    engine.fill_bytes(&mut block);
    assert_eq!(
        block,
        [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7
        ]
    );
}

#[test]
fn cold_and_failed_sources_never_emit_or_restore_saved_readiness() {
    let mut generator = Generator::unavailable(domain());
    let mut output = [0xa5; 32];
    assert_eq!(
        generator.fill(domain().at(1), &mut output),
        Err(Error::Accounting(entropy::Error::Unavailable))
    );
    assert_eq!(output, [0xa5; 32]);
    let mut generator = seeded();
    generator.source_failed();
    assert_eq!(
        generator.fill(domain().at(2), &mut output),
        Err(Error::Accounting(entropy::Error::Unavailable))
    );
    let mut reused_seed = [0x19; 32];
    assert_eq!(
        generator.reseed_after_authorized_source(domain().at(3), 1, &mut reused_seed),
        Err(Error::Accounting(entropy::Error::StaleGeneration))
    );
    assert_eq!(reused_seed, [0; 32]);
    assert_eq!(output, [0xa5; 32]);
}

#[test]
fn delivery_failure_never_refunds_bytes_or_replays_a_stream_range() {
    let mut generator = seeded();
    let mut reference = seeded();
    let mut undelivered = [0; 32];
    let first = generator.fill(domain().at(2), &mut undelivered).unwrap();
    // The hypothetical transport refuses this first successful generation.
    // There is no refund call. The next request must get different bytes.
    let mut next = [0; 32];
    let second = generator.fill(domain().at(2), &mut next).unwrap();
    let mut all = [0; 64];
    reference.fill(domain().at(2), &mut all).unwrap();
    assert_eq!(first.request, 1);
    assert_eq!(second.request, 2);
    assert_eq!(first.seed_generation, 1);
    assert_eq!(first.bytes, 32);
    assert_ne!(undelivered, next);
    assert_eq!(&all[..32], &undelivered);
    assert_eq!(&all[32..], &next);
}

#[test]
fn invalid_lengths_preserve_output_budget_but_record_actual_time() {
    let mut generator = seeded();
    let mut oversized = [0xa5; MAX_REQUEST_BYTES + 1];
    assert_eq!(
        generator.fill(domain().at(10), &mut oversized),
        Err(Error::Accounting(entropy::Error::InvalidRequest))
    );
    assert_eq!(oversized, [0xa5; MAX_REQUEST_BYTES + 1]);
    let mut output = [0xa5; 1];
    assert_eq!(
        generator.fill(domain().at(9), &mut output),
        Err(Error::Accounting(entropy::Error::Clock(
            ev_time_contract::Error::ClockRegression
        )))
    );
    assert_eq!(output, [0xa5; 1]);
    assert_eq!(
        generator.fill(domain().at(11), &mut output),
        Err(Error::Accounting(entropy::Error::Unavailable))
    );
}

#[test]
fn finite_output_and_time_require_new_actual_seeding() {
    let mut generator = seeded();
    let mut block = [0; MAX_REQUEST_BYTES];
    for _ in 0..OUTPUT_PER_SEED / MAX_REQUEST_BYTES as u64 {
        generator.fill(domain().at(2), &mut block).unwrap();
    }
    let mut refused = [0xa5; 1];
    assert_eq!(
        generator.fill(domain().at(2), &mut refused),
        Err(Error::Accounting(entropy::Error::ReseedRequired))
    );
    assert_eq!(refused, [0xa5; 1]);
    let mut seed = [0x22; 32];
    generator
        .reseed_after_authorized_source(domain().at(3), 2, &mut seed)
        .unwrap();
    assert_eq!(
        generator.fill(domain().at(3 + RESEED_TICKS), &mut refused),
        Err(Error::Accounting(entropy::Error::ReseedRequired))
    );
    assert_eq!(refused, [0xa5; 1]);
}

#[test]
fn delayed_owner_refresh_preserves_lifetime_sequence_and_refuses_clock_rollback() {
    let mut generator = seeded();
    let mut first = [0; 32];
    assert_eq!(
        generator.fill(domain().at(2), &mut first).unwrap().request,
        1
    );
    let later = 2 * RESEED_TICKS;
    let mut output = [0xa5; 32];
    assert_eq!(
        generator.fill(domain().at(later), &mut output),
        Err(Error::Accounting(entropy::Error::ReseedRequired))
    );
    assert_eq!(output, [0xa5; 32]);

    // Model the adapter's genuine new acquisition, not saved readiness. The
    // deterministic seed here tests accounting only, never source quality.
    generator.source_failed();
    let mut seed = [0x27; 32];
    generator
        .reseed_after_authorized_source(domain().at(later + 1), 2, &mut seed)
        .unwrap();
    assert_eq!(seed, [0; 32]);
    let receipt = generator.fill(domain().at(later + 1), &mut output).unwrap();
    assert_eq!(receipt.request, 2);
    assert_eq!(receipt.seed_generation, 2);
    assert_eq!(receipt.bytes, 32);
    assert_ne!(output, first);

    generator.source_failed();
    let mut seed = [0x39; 32];
    assert_eq!(
        generator.reseed_after_authorized_source(domain().at(later), 3, &mut seed),
        Err(Error::Accounting(entropy::Error::Clock(
            ev_time_contract::Error::ClockRegression
        )))
    );
    assert_eq!(seed, [0; 32]);
    let mut refused = [0xa5; 32];
    assert_eq!(
        generator.fill(domain().at(later + 2), &mut refused),
        Err(Error::Accounting(entropy::Error::Unavailable))
    );
    assert_eq!(refused, [0xa5; 32]);
}

#[test]
fn generations_select_distinct_upstream_substreams_without_claiming_entropy() {
    let mut generator = seeded();
    let mut first = [0; 32];
    generator.fill(domain().at(2), &mut first).unwrap();
    let mut same_test_seed = [0x19; 32];
    generator
        .reseed_after_authorized_source(domain().at(3), 2, &mut same_test_seed)
        .unwrap();
    let mut second = [0; 32];
    generator.fill(domain().at(3), &mut second).unwrap();
    assert_ne!(first, second);
    assert_eq!(same_test_seed, [0; 32]);
}

#[test]
fn clock_domain_and_request_exhaustion_fail_without_exposing_output() {
    let mut generator = seeded();
    let mut out = [0xa5; 32];
    assert_eq!(
        generator.fill(Domain::new(8).unwrap().at(2), &mut out),
        Err(Error::Accounting(entropy::Error::Clock(
            ev_time_contract::Error::DifferentBoot
        )))
    );
    assert_eq!(out, [0xa5; 32]);
    let mut generator = seeded();
    generator.request = u64::MAX;
    assert_eq!(
        generator.fill(domain().at(2), &mut out),
        Err(Error::RequestSequenceExhausted)
    );
    assert_eq!(out, [0xa5; 32]);
    let mut seed = [0x22; 32];
    generator
        .reseed_after_authorized_source(domain().at(3), 2, &mut seed)
        .unwrap();
    assert_eq!(
        generator.fill(domain().at(3), &mut out),
        Err(Error::RequestSequenceExhausted)
    );
}
