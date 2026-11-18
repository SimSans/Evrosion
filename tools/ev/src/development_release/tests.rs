use super::*;
pub(crate) struct Scratch(pub(crate) PathBuf);
impl Scratch {
    pub(crate) fn new() -> Self {
        let root = crate::build::unique_directory(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/test-tmp/development-signing-tests"),
            "authority",
        )
        .unwrap();
        fs::create_dir_all(root.join("tools/m6/fixtures")).unwrap();
        Self(root)
    }
    pub(crate) fn provision(&self) -> Authority {
        provision(
            &self.0,
            Author {
                version: 1,
                not_before: 0,
                expires: 1000,
            },
        )
        .unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn specs() -> [TargetSpec; 2] {
    core::array::from_fn(|i| TargetSpec {
        name: [i as u8 + 1; 32],
        version: 1,
        length: 1,
        sha256: digest(&[i as u8]),
        generation: [3; 32],
        release: [4; 32],
        source_revision: [5; 32],
        build: [6; 32],
        provenance: [7; 32],
        contract: [8; 32],
    })
}
fn author() -> Author {
    Author {
        version: 1,
        not_before: 100,
        expires: 200,
    }
}

#[test]
fn first_party_public_anchor_is_self_consistent_development_only() {
    let bytes = include_bytes!("../../../../tools/m6/fixtures/development-root.bin");
    let provenance: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../tools/m6/fixtures/development-authority.json"
    ))
    .unwrap();
    let root = TrustedRoot::provisioned(bytes, binding()).unwrap();
    assert_eq!(root.common().version, 1);
    assert_eq!(root.common().not_before, 1_794_441_600);
    assert_eq!(root.common().expires, 1_825_977_600);
    assert_eq!(provenance["root_sha256"], hex(&digest(bytes)));
    assert_eq!(provenance["thresholds"], serde_json::json!([2, 1, 1, 1]));
    assert_eq!(
        provenance["authority"],
        "DEVELOPMENT ONLY; not Official Evrosion"
    );
}

#[test]
fn actual_five_key_authority_is_private_disjoint_and_root_requires_both_signatures() {
    let dir = Scratch::new();
    let a = dir.provision();
    let loaded = Authority::load(&dir.0).unwrap();
    assert_eq!(a.root(), loaded.root());
    let e = Envelope::parse(a.root()).unwrap();
    let root = md::Root::parse(&e).unwrap();
    assert_eq!(e.signature_count(), 2);
    let single = signed(Role::Root, e.payload(), &[&a.keys[0]]).unwrap();
    assert!(TrustedRoot::provisioned(&single, binding()).is_err());
    let foreign = Scratch::new();
    let other = foreign.provision();
    assert!(a.keys.iter().all(|k| {
        other
            .keys
            .iter()
            .all(|o| public(k).unwrap() != public(o).unwrap())
    }));
    let public_json = read_public(&dir.0.join(PUBLIC_FILE), 16384).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&public_json).unwrap();
    assert_eq!(parsed["thresholds"], serde_json::json!([2, 1, 1, 1]));
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 5);
    assert!(
        !String::from_utf8(public_json.clone())
            .unwrap()
            .contains(".seed")
    );
    let private = directory(&dir.0).unwrap();
    assert_eq!(
        fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in NAMES {
        let path = private.join(name);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut seed = fs::read(path).unwrap();
        let encoded = hex(&seed);
        assert!(
            !String::from_utf8(public_json.clone())
                .unwrap()
                .contains(&encoded)
        );
        seed.zeroize();
    }
    let release = a.sign(author(), &specs()).unwrap();
    release.check_signatures(a.root()).unwrap();
    for (role, bytes, key) in [
        (Role::Targets, &release.targets, 3),
        (Role::Snapshot, &release.snapshot, 4),
        (Role::Timestamp, &release.timestamp, 2),
    ] {
        let envelope = Envelope::parse(bytes).unwrap();
        let wrong = signed(role, envelope.payload(), &[&a.keys[key]]).unwrap();
        assert!(
            root.authenticate(&Envelope::parse(&wrong).unwrap())
                .is_err()
        );
    }
}

#[test]
fn missing_corrupt_wrong_or_exposed_private_material_never_recreates_authority() {
    for mode in 0..5 {
        let dir = Scratch::new();
        let a = dir.provision();
        let root = a.root().to_vec();
        let private = directory(&dir.0).unwrap();
        let path = private.join(NAMES[0]);
        match mode {
            0 => fs::remove_file(&path).unwrap(),
            1 => fs::write(&path, [1, 2]).unwrap(),
            2 => {
                let other = Scratch::new();
                let _ = other.provision();
                fs::copy(directory(&other.0).unwrap().join(NAMES[0]), &path).unwrap();
            }
            3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(private.join(NAMES[1]), &path).unwrap();
            }
        }
        assert!(Authority::load(&dir.0).is_err());
        assert!(provision(&dir.0, author()).is_err());
        assert_eq!(fs::read(dir.0.join(ROOT_FILE)).unwrap(), root);
        if mode == 0 {
            assert!(!path.exists());
        }
        if mode == 1 {
            assert_eq!(fs::metadata(path).unwrap().len(), 2);
        }
    }
}

#[test]
fn signatures_links_artifact_bytes_and_author_limits_are_checked_without_time_authority() {
    let dir = Scratch::new();
    let a = dir.provision();
    let specs = specs();
    let mut release = a.sign(author(), &specs).unwrap();
    release.check_signatures(a.root()).unwrap();
    let envelope = Envelope::parse(&release.targets).unwrap();
    let targets = md::Targets::parse(&envelope).unwrap();
    for (i, t) in targets.iter().enumerate() {
        t.verify_bytes(&[i as u8], 262144).unwrap();
        assert!(t.verify_bytes(&[i as u8 + 1], 262144).is_err());
    }
    let last = release.targets.len() - 1;
    release.targets[last] ^= 1;
    assert!(release.check_signatures(a.root()).is_err());
    let mut release = a.sign(author(), &specs).unwrap();
    let different = a
        .sign(
            Author {
                version: 2,
                ..author()
            },
            &specs,
        )
        .unwrap();
    release.snapshot = different.snapshot;
    assert!(release.check_signatures(a.root()).is_err());
    assert!(
        a.sign(
            Author {
                expires: 701,
                ..author()
            },
            &specs
        )
        .is_err()
    );
    assert!(
        a.sign(
            Author {
                version: 0,
                ..author()
            },
            &specs
        )
        .is_err()
    );
    let mut wrong = specs;
    wrong[1].generation = [9; 32];
    assert!(a.sign(author(), &wrong).is_err());
}
