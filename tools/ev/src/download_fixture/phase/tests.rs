use super::*;
use crate::development_release::{binding, tests::Scratch};
use ev_release_trust::{
    metadata,
    signature::Envelope,
    verifier::{self, ReplayState, TrustedRoot},
};
use ev_time_contract::{
    Domain,
    freshness::{QualifiedWindow, Time, UtcInterval},
};
fn author(version: u64) -> Author {
    Author {
        version,
        not_before: 100,
        expires: 200,
    }
}
fn synthetic_test_time() -> (Time, ev_time_contract::Instant) {
    // TEST ONLY consumer evidence. The Host fixture never creates this value
    // or treats its author timestamps as a qualification source.
    let d = Domain::new(77).unwrap();
    (
        Time::Qualified(
            QualifiedWindow::new(d.at(10), d.at(20), UtcInterval::new(110, 111).unwrap()).unwrap(),
        ),
        d.at(15),
    )
}
fn verify<'a>(
    root: &TrustedRoot<'_>,
    state: &ReplayState,
    signed: &'a SignedRelease,
) -> Result<Verified<'a>, verifier::Error> {
    let (time, now) = synthetic_test_time();
    verifier::verify_bundle(
        root,
        state,
        verifier::Bundle {
            targets: &signed.targets,
            snapshot: &signed.snapshot,
            timestamp: &signed.timestamp,
        },
        time,
        now,
        verifier::Policy::new(8, 262144).unwrap(),
    )
}
fn package(phase: FixturePhase) -> crate::native_package::BuiltPackage {
    crate::native_package::downloaded_hello(
        include_bytes!("../../../../../kernel/fixtures/bootstrap-static-v1.elf"),
        [9; 32],
        phase.variant(),
    )
    .unwrap()
}
fn spec(phase: FixturePhase, p: &crate::native_package::BuiltPackage) -> TargetSpec {
    target_spec(
        phase,
        &Candidate {
            source: [9; 32],
            bytes: &p.bytes,
            package: p.package,
            build: p.build,
            descriptor: p.descriptor,
            image: p.executable,
        },
    )
}

#[test]
fn signed_b_then_c_retains_one_app_floor_and_refuses_old_remote_b_even_if_reauthored() {
    let dir = Scratch::new();
    let authority = dir.provision();
    let root = TrustedRoot::provisioned(authority.root(), binding()).unwrap();
    let initial = ReplayState::initial(&root);
    let b = package(FixturePhase::B);
    let c = package(FixturePhase::C);
    let bs = spec(FixturePhase::B, &b);
    let cs = spec(FixturePhase::C, &c);
    assert_eq!(bs.name, cs.name);
    assert_eq!(bs.name, logical_target_name());
    assert_eq!((bs.version, cs.version), (2, 3));
    assert_ne!(bs.generation, cs.generation);
    assert_ne!(bs.release, cs.release);
    let signed_b = authority.sign_candidate(author(1), bs).unwrap();
    let checked_b = verify(&root, &initial, &signed_b).unwrap();
    select_phase(FixturePhase::B, &checked_b, &b.bytes).unwrap();
    let after_b = *checked_b.proposed();
    assert_eq!(after_b.targets().iter().flatten().count(), 1);
    assert_eq!(
        after_b.targets().iter().flatten().next().unwrap().version,
        2
    );
    let signed_c = authority.sign_candidate(author(2), cs).unwrap();
    let checked_c = verify(&root, &after_b, &signed_c).unwrap();
    select_phase(FixturePhase::C, &checked_c, &c.bytes).unwrap();
    let after_c = *checked_c.proposed();
    assert_eq!(after_c.targets().iter().flatten().count(), 1);
    assert_eq!(
        after_c.targets().iter().flatten().next().unwrap().version,
        3
    );
    assert_eq!(after_c.roles().map(|r| r.unwrap().version), [2, 2, 2]);
    assert!(after_c.utc_floor() >= after_b.utc_floor());
    assert!(matches!(
        verify(&root, &after_c, &signed_b),
        Err(verifier::Error::Rollback)
    ));
    // Fresh role metadata cannot disguise the old artifact as a new target.
    let reauthored_b = authority.sign_candidate(author(3), bs).unwrap();
    assert!(matches!(
        verify(&root, &after_c, &reauthored_b),
        Err(verifier::Error::Rollback)
    ));
    assert_eq!(*checked_c.proposed(), after_c);
    // Those refused remote transitions neither mutate nor authorize local B.
    // Its retained bytes still parse/hash; local KnownGood authorization and
    // recovery admission remain separate OS mechanisms, absent from this API.
    assert_eq!(hash(&b.bytes), bs.sha256);
    assert_eq!(
        ev_zion::Package::parse(&b.bytes)
            .unwrap()
            .app()
            .claimed_app
            .bytes(),
        crate::native_package::HELLO_APP_ID
    );
    assert!(select_phase(FixturePhase::B, &checked_c, &b.bytes).is_err());
    let payload = Envelope::parse(&signed_c.targets).unwrap();
    assert_eq!(metadata::Targets::parse(&payload).unwrap().count(), 1);
}

#[test]
fn same_claimed_app_under_a_new_target_name_cannot_reset_expected_selection() {
    let dir = Scratch::new();
    let authority = dir.provision();
    let root = TrustedRoot::provisioned(authority.root(), binding()).unwrap();
    let b = package(FixturePhase::B);
    let c = package(FixturePhase::C);
    let sb = authority
        .sign_candidate(author(1), spec(FixturePhase::B, &b))
        .unwrap();
    let vb = verify(&root, &ReplayState::initial(&root), &sb).unwrap();
    let retained = *vb.proposed();
    let mut renamed = spec(FixturePhase::C, &c);
    renamed.name = hash(b"attacker-nominated-unrelated-target-name");
    let signed = authority.sign_candidate(author(2), renamed).unwrap();
    // The generic multi-target mechanism permits a different target, as
    // designed. Independently expected app selection must still refuse it.
    let generic = verify(&root, &retained, &signed).unwrap();
    assert!(select_phase(FixturePhase::C, &generic, &c.bytes).is_err());
    assert_eq!(retained.targets().iter().flatten().count(), 1);
    let original = spec(FixturePhase::B, &b);
    let mut second = renamed;
    second.generation = original.generation;
    second.release = original.release;
    let wrong = authority.sign(author(2), &[original, second]).unwrap();
    let multi = verify(&root, &retained, &wrong).unwrap();
    assert!(select_phase(FixturePhase::B, &multi, &b.bytes).is_err());
}

#[test]
fn authenticated_target_still_requires_the_actual_package_build_source_and_descriptor() {
    let dir = Scratch::new();
    let authority = dir.provision();
    let root = TrustedRoot::provisioned(authority.root(), binding()).unwrap();
    let c = package(FixturePhase::C);
    for field in 0..3 {
        let mut wrong = spec(FixturePhase::C, &c);
        match field {
            0 => wrong.build[0] ^= 1,
            1 => wrong.contract[0] ^= 1,
            _ => wrong.source_revision[0] ^= 1,
        }
        let signed = authority.sign_candidate(author(2), wrong).unwrap();
        let generic = verify(&root, &ReplayState::initial(&root), &signed).unwrap();
        assert!(select_phase(FixturePhase::C, &generic, &c.bytes).is_err());
    }
}

fn public_transport_model(
    phase: FixturePhase,
    authority: &Authority,
    directory: &Path,
) -> PhaseFixture {
    // Public signed model material, not the independently built production
    // absent-bank B/C cohort and never runtime/executable acceptance evidence.
    let p = package(phase);
    let signed = authority
        .sign_candidate(author(phase.initial_metadata_version()), spec(phase, &p))
        .unwrap();
    PhaseFixture {
        phase,
        directory: directory.to_path_buf(),
        assets: [
            ("/release/root.bin", authority.root().to_vec()),
            ("/release/targets.bin", signed.targets),
            ("/release/snapshot.bin", signed.snapshot),
            ("/release/timestamp.bin", signed.timestamp),
            ("/artifacts/hello.zion", p.bytes),
        ],
    }
}
#[test]
fn actual_owned_tcp_server_serves_only_exact_public_phase_bytes_and_switches_once() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        thread,
        time::{Duration, Instant},
    };
    let scratch = Scratch::new();
    let authority = scratch.provision();
    let b = public_transport_model(FixturePhase::B, &authority, &scratch.0.join("model-b"));
    let expected: Vec<_> = [
        "/release/timestamp.bin",
        "/release/snapshot.bin",
        "/release/targets.bin",
        "/artifacts/hello.zion",
    ]
    .into_iter()
    .map(|path| (path, b.asset(path).unwrap().to_vec()))
    .collect();
    let (server, address) =
        crate::network_fixture::Fixture::acquisition_pending_for_tests().unwrap();
    let fetch = |path: &str| {
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(
                std::format!("GET {path} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        response
    };
    assert_eq!(server.acquisition_receipt().unwrap()["phase"], "pending");
    assert!(fetch("/release/timestamp.bin").starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    let direct_c = public_transport_model(FixturePhase::C, &authority, &scratch.0.join("direct-c"));
    assert!(
        server
            .replace_phase(direct_c)
            .unwrap_err()
            .contains("pending->B->C")
    );
    assert_eq!(server.acquisition_receipt().unwrap()["phase"], "pending");
    assert_eq!(
        server.acquisition_receipt().unwrap()["history"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    server.replace_phase(b).unwrap();
    for (path, body) in &expected {
        assert_eq!(fetch(path),[std::format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes(),body].concat());
    }
    let c = public_transport_model(FixturePhase::C, &authority, &scratch.0.join("model-c"));
    let mut false_c =
        public_transport_model(FixturePhase::B, &authority, &scratch.0.join("mislabeled-b"));
    false_c.phase = FixturePhase::C;
    assert!(server.replace_phase(false_c).is_err());
    let cbytes = c.asset("/artifacts/hello.zion").unwrap().to_vec();
    assert_ne!(expected.last().unwrap().1, cbytes);
    server.replace_phase(c).unwrap();
    assert!(fetch("/artifacts/hello.zion").ends_with(&cbytes));
    assert!(fetch("/release/root.bin").starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    assert!(
        server
            .replace_phase(public_transport_model(
                FixturePhase::B,
                &authority,
                &scratch.0.join("old-b")
            ))
            .is_err()
    );
    let provenance = server.acquisition_receipt().unwrap();
    assert_eq!(provenance["phase"], "c");
    assert_eq!(provenance["history"].as_array().unwrap().len(), 2);
    assert_eq!(provenance["consumer_authorization_claim"], false);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let snapshot = server.snapshot().unwrap();
        if snapshot.completed == 7 {
            assert_eq!(snapshot.observed, 7);
            assert_eq!(snapshot.omitted, 0);
            assert_eq!(snapshot.exchanges[1].response, fetch_cached(&expected[0].1));
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}
fn fetch_cached(body: &[u8]) -> Vec<u8> {
    [std::format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes(),body].concat()
}
#[test]
fn direct_b_server_constructor_allows_one_later_checked_c_without_skipping_pending_rules() {
    let scratch = Scratch::new();
    let authority = scratch.provision();
    let b = public_transport_model(FixturePhase::B, &authority, &scratch.0.join("direct-b"));
    let (server, _) = crate::network_fixture::Fixture::acquisition_for_tests(b).unwrap();
    assert_eq!(server.acquisition_receipt().unwrap()["phase"], "b");
    assert_eq!(
        server.acquisition_receipt().unwrap()["history"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        server
            .replace_phase(public_transport_model(
                FixturePhase::B,
                &authority,
                &scratch.0.join("repeat-b"),
            ))
            .is_err()
    );
    server
        .replace_phase(public_transport_model(
            FixturePhase::C,
            &authority,
            &scratch.0.join("later-c"),
        ))
        .unwrap();
    assert!(
        server
            .replace_phase(public_transport_model(
                FixturePhase::C,
                &authority,
                &scratch.0.join("repeat-c"),
            ))
            .is_err()
    );
    assert_eq!(server.acquisition_receipt().unwrap()["phase"], "c");
    assert_eq!(
        server.acquisition_receipt().unwrap()["history"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        server.acquisition_receipt().unwrap()["consumer_authorization_claim"],
        false
    );
}
