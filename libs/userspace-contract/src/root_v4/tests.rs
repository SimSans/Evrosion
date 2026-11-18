extern crate std;
use super::*;
#[test]
fn measured_v4_root_capacity_is_separate_bounded_layout_metadata() {
    assert_eq!(
        (
            ROOT_MAX_IMAGE_PAGES,
            ROOT_MAX_PRIVATE_PAGES,
            ROOT_MAX_PRIVATE_FRAMES
        ),
        (240, 244, 246)
    );
    let layout = layout_description();
    assert_eq!(&layout[944..952], b"EVRCAP04");
    assert_eq!(&layout[952..960], &240u64.to_le_bytes());
    assert_eq!(&layout[960..968], &244u64.to_le_bytes());
    assert_eq!(&layout[968..976], &246u64.to_le_bytes());
    assert_eq!(&layout[976..984], b"EVRTC004");
}
use crate::root_v2::{self, catalogue as base, native};

fn context() -> Context {
    Context {
        epoch: 1,
        incarnation: 2,
        process: 3,
        limits: ROOT_LIMITS,
        manifest: [4; 32],
        authority: [5; 32],
    }
}
fn startup() -> [u8; SIZE] {
    encode_full_graph(context(), core::array::from_fn(|i| 100 + i as u64)).unwrap()
}
fn base_description() -> base::Description {
    base::Description {
        root_image: [1; 32],
        kernel_input: [2; 32],
        graph: [3; 32],
        app_id: [4; 16],
        package: [5; 32],
        app_build: [6; 32],
        provenance: base::Provenance::Zion,
        restart_attempts: 3,
        restart_window: 60000,
        images: core::array::from_fn(|i| base::Image {
            role: root_v2::graph::CHILDREN[i].image(),
            image: [i as u8 + 10; 32],
            descriptor: [i as u8 + 20; 32],
            abi: crate::ABI,
            limits: base::CHILD_LIMITS,
            display_layout: i == 5,
            grants: catalogue::BASE_ROLE_COUNTS[i],
            roles: [i as u8 + 30; 32],
        }),
    }
}
fn base_bytes() -> [u8; base::SIZE] {
    catalogue::encode_base(base_description()).unwrap()
}
fn im(hash: u8, roles: u8, limits: [u64; 4]) -> catalogue::Image {
    catalogue::Image {
        image: [hash; 32],
        descriptor: [hash + 1; 32],
        abi: crate::ABI,
        limits,
        roles: [roles; 32],
    }
}
fn catalogue_bytes() -> [u8; catalogue::SIZE] {
    catalogue::encode(catalogue::Description {
        base: &base_bytes(),
        app_b: im(41, 34, base::CHILD_LIMITS),
        bad_shell: im(46, 30, base::CHILD_LIMITS),
        boot_mode: catalogue::BootMode::Standalone,
        package_b: [43; 32],
        package_b_build: [44; 32],
        package_a_bytes: 4097,
        package_b_bytes: PACKAGE_MAX_BYTES,
        net_driver: im(60, 61, graph::Child::NetDriver.limits()),
        net_service: im(62, 63, graph::Child::NetService.limits()),
        device: catalogue::DeviceWitness {
            mac: catalogue::REFERENCE_MAC,
            model_source_sha256: [70; 32],
            emulator_binary_sha256: [71; 32],
        },
        network_policy: catalogue::NetworkPolicy {
            allowed_ipv4: [10, 0, 2, 2],
            remote_port: 8080,
            local_port: 49152,
            dns_name: "example.org",
        },
        layout_measurement: [45; 32],
    })
    .unwrap()
}

#[test]
fn exact_profile_is_independent_and_preserves_original_role_triples() {
    assert_eq!(
        (VERSION, PROFILE, SIZE, MAX_GRANTS, CURRENT_GRANTS),
        (4, 4, 912, 32, 29)
    );
    let bytes = startup();
    let graph = FullGraph::parse(&bytes).unwrap();
    assert_eq!(graph.handle(Role::NetServiceImage), 123);
    let actual = graph.context();
    let expected = context();
    assert_eq!(
        (
            actual.epoch,
            actual.incarnation,
            actual.process,
            actual.limits,
            actual.manifest,
            actual.authority
        ),
        (
            expected.epoch,
            expected.incarnation,
            expected.process,
            expected.limits,
            expected.manifest,
            expected.authority
        )
    );
    for (actual, old) in ROLES[..22].iter().zip(native::ROLES) {
        assert_eq!(
            (actual.role.selector(), actual.kind, actual.rights),
            (old.selector, old.kind, old.rights)
        );
    }
    assert!(native::FullGraph::parse(&bytes).is_err());
    assert!(root_v2::FullGraph::parse(&bytes).is_err());
    assert!(crate::Bootstrap::parse(&bytes).is_err());
    let old =
        native::encode_full_graph(context(), core::array::from_fn(|i| 100 + i as u64)).unwrap();
    assert!(FullGraph::parse(&old).is_err());
    let mut padded = [0; SIZE];
    padded[..native::SIZE].copy_from_slice(&old);
    padded[..8].copy_from_slice(b"EVROOT04");
    padded[8..10].copy_from_slice(&VERSION.to_le_bytes());
    padded[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
    padded[12..14].copy_from_slice(&PROFILE.to_le_bytes());
    assert!(Bootstrap::parse(&padded).is_ok());
    assert!(matches!(FullGraph::parse(&padded), Err(Error::Roles)));
}

#[test]
fn pre_v4_actual_service_and_native3_serializers_remain_byte_identical() {
    let context = || Context {
        limits: [16384, 512, 1, 1],
        ..context()
    };
    // Captured by compiling the actual pre-v4 SDK from compact snapshot03,
    // rather than deriving an expected value from the v4 serializer under test.
    assert_eq!(
        crate::encode(
            context(),
            &[Grant {
                selector: 1,
                handle: 100,
                kind: 1,
                rights: 1
            }]
        )
        .unwrap(),
        *include_bytes!("fixtures/service-startup.bin")
    );
    assert_eq!(
        native::encode_full_graph(context(), core::array::from_fn(|i| 100 + i as u64)).unwrap(),
        *include_bytes!("fixtures/native3-startup.bin")
    );
    assert_eq!(
        native::manifest_profile(ManifestInputs {
            root_image: [6; 32],
            catalogue: [7; 32],
            authority: [5; 32],
            limits: context().limits,
            restart_attempts: 3,
            restart_window: 60000
        })
        .unwrap(),
        *include_bytes!("fixtures/native3-manifest.bin")
    );
}
#[test]
fn syntax_spare_slots_never_silently_expand_full_graph() {
    let mut grants = std::vec::Vec::new();
    for (i, r) in ROLES.into_iter().enumerate() {
        grants.push(Grant {
            selector: r.role.selector(),
            handle: 100 + i as u64,
            kind: r.kind,
            rights: r.rights,
        });
    }
    for i in 29..32 {
        grants.push(Grant {
            selector: i + 1,
            handle: 100 + i,
            kind: 1,
            rights: 1,
        });
    }
    let raw = encode(context(), &grants).unwrap();
    assert_eq!(Bootstrap::parse(&raw).unwrap().grants().len(), 32);
    assert!(matches!(FullGraph::parse(&raw), Err(Error::Roles)));
    grants.push(Grant {
        selector: 33,
        handle: 133,
        kind: 1,
        rights: 1,
    });
    assert_eq!(encode(context(), &grants), Err(Error::GrantCount));
}
#[test]
fn aliases_order_reserved_count_and_context_errors_refuse_before_access() {
    let bytes = startup();
    for at in [
        14,
        15,
        137,
        143,
        HEADER + 17,
        HEADER + 20,
        HEADER + CURRENT_GRANTS * GRANT_BYTES,
        SIZE - 1,
    ] {
        let mut b = bytes;
        b[at] = 1;
        assert!(matches!(Bootstrap::parse(&b), Err(Error::Reserved)));
    }
    let mut b = bytes;
    put(&mut b, HEADER + GRANT_BYTES + 8, 100);
    assert!(matches!(Bootstrap::parse(&b), Err(Error::Alias)));
    let mut b = bytes;
    put(&mut b, HEADER + GRANT_BYTES, 1);
    assert!(matches!(Bootstrap::parse(&b), Err(Error::Order)));
    let mut b = bytes;
    b[HEADER + 18] = 5;
    assert!(Bootstrap::parse(&b).is_ok());
    assert!(matches!(FullGraph::parse(&b), Err(Error::Roles)));
    for count in [0, 33, 255] {
        let mut b = bytes;
        b[136] = count;
        assert!(matches!(Bootstrap::parse(&b), Err(Error::GrantCount)));
    }
    for at in [16, 24, 32, 40, 48, 56, 64] {
        let mut b = bytes;
        put(&mut b, at, 0);
        assert!(Bootstrap::parse(&b).is_err());
    }
    for at in [40, 48, 56, 64] {
        let mut b = bytes;
        put(&mut b, at, u64::MAX);
        assert!(matches!(Bootstrap::parse(&b), Err(Error::Limits)));
    }
    let mut b = bytes;
    b[72..104].fill(0);
    assert!(matches!(Bootstrap::parse(&b), Err(Error::Identity)));
}
#[test]
fn manifest_has_distinct_magic_abi_size_and_exact_twenty_eight_roles() {
    let manifest = manifest_profile(ManifestInputs {
        root_image: [6; 32],
        catalogue: [7; 32],
        authority: [5; 32],
        limits: context().limits,
        restart_attempts: 3,
        restart_window: 60000,
    })
    .unwrap();
    assert_eq!(manifest.len(), 1136);
    assert_eq!(&manifest[..8], b"EVBM0004");
    assert_eq!(&manifest[48..80], &ABI);
    assert_eq!(manifest[160], 29);
    assert_eq!(&manifest[168..174], &[4, 0, 0x90, 3, 4, 0]);
    for (i, r) in ROLES.into_iter().enumerate() {
        let at = MANIFEST_HEADER + i * 32;
        assert_eq!(word(&manifest, at), r.role.selector());
        assert_eq!(manifest[at + 8], r.kind);
        assert_eq!(&manifest[at + 10..at + 12], &r.rights.to_le_bytes());
    }
}
#[test]
fn graph_reuses_original_children_routes_grants_and_reserves_events_wire() {
    for (i, old_child) in root_v2::graph::CHILDREN.into_iter().enumerate() {
        let child = graph::CHILDREN[i];
        assert_eq!(child.index(), old_child.index());
        assert_eq!(child.image().selector(), old_child.image().selector());
        for (actual, old) in graph::grants(child).zip(root_v2::graph::grants(old_child)) {
            assert_eq!((actual.kind, actual.rights), (old.kind, old.rights));
            match (actual.source, old.source) {
                (graph::Source::Root(a), root_v2::graph::Source::Root(b)) => {
                    assert_eq!(a.selector(), b.selector())
                }
                (graph::Source::Endpoint(a), root_v2::graph::Source::Endpoint(b)) => {
                    assert_eq!(a.wire_index(), b.index())
                }
                _ => panic!("legacy source changed"),
            }
        }
    }
    for (i, old) in root_v2::graph::CHANNELS.into_iter().enumerate() {
        let new = graph::CHANNELS[i];
        assert_eq!(new.wire_index(), old.index());
        assert_eq!(new.receiver().index(), old.receiver().index());
        assert_eq!(new.delivery(), old.delivery());
    }
    assert_eq!(graph::CHANNELS.len(), 17);
    assert!(
        graph::CHANNELS
            .iter()
            .all(|c| c.wire_index() != graph::ROOT_EVENTS_WIRE)
    );
    assert_eq!(graph::Channel::NetDriverRpc.wire_index(), 16);
    assert_eq!(graph::Channel::NetClientRpc.wire_index(), 17);
    assert_eq!(graph::WIRE_SLOTS, 18);
    for channel in graph::CHANNELS {
        assert_eq!(
            graph::Channel::from_wire_index(channel.wire_index()),
            Some(channel)
        );
    }
    for index in [15, 18, usize::MAX] {
        assert_eq!(graph::Channel::from_wire_index(index), None);
    }
    for child in graph::CHILDREN {
        assert!(graph::grants(child).len() <= crate::MAX_GRANTS);
    }
    assert_eq!(graph::grants(graph::Child::NetDriver).len(), 4);
    assert_eq!(graph::grants(graph::Child::NetService).len(), 5);
    assert!(graph::grants(graph::Child::App).all(|g| !matches!(
        g.source,
        graph::Source::Root(Role::NicPorts | Role::NicWindow | Role::NetClientWindow)
            | graph::Source::Endpoint(graph::Channel::NetDriverRpc | graph::Channel::NetClientRpc)
    )));
    assert!(graph::grants(graph::Child::NetService).all(|g| g.kind != 7));
}

#[test]
fn note_is_a_separate_root_source_and_seventh_app_role_without_file_or_network_access() {
    let bytes = startup();
    let full = FullGraph::parse(&bytes).unwrap();
    assert_ne!(full.handle(Role::NoteWindow), full.handle(Role::AppFile));
    let note = full
        .grants()
        .find(|g| g.selector == Role::NoteWindow.selector())
        .unwrap();
    assert_eq!((note.kind, note.rights), (1, 231));
    let app = graph::grants(graph::Child::App).collect::<std::vec::Vec<_>>();
    assert_eq!(app.len(), 7);
    assert_eq!(
        app[6],
        graph::Grant {
            kind: 1,
            rights: 7,
            source: graph::Source::Root(Role::NoteWindow)
        }
    );
    for child in [
        graph::Child::File,
        graph::Child::Block,
        graph::Child::NetDriver,
        graph::Child::NetService,
    ] {
        assert!(
            graph::grants(child).all(|grant| grant.source != graph::Source::Root(Role::NoteWindow))
        );
    }
    assert_eq!(
        (ROOT_NOTE_PAGE, APP_NOTE_PAGE, NIC_WINDOW_PAGE),
        (506, 507, 508)
    );
}

#[test]
fn v4_base_is_actual_app7_metadata_and_public_legacy_codecs_stay_strict() {
    assert!(matches!(
        base::encode(base_description()),
        Err(base::Error::Profile)
    ));
    let bytes = base_bytes();
    assert!(matches!(
        base::Catalogue::decode(&bytes),
        Err(base::Error::Profile)
    ));
    let full = catalogue_bytes();
    let v4 = catalogue::Catalogue::decode(&full).unwrap();
    assert_eq!(v4.base().images().nth(4).unwrap().grants, 7);
    assert_eq!(full[catalogue::BASE_SIZE + 160 + 137], 7);
    let mut app6 = full;
    app6[base::HEADER + 4 * base::IMAGE_BYTES + 137] = 6;
    assert!(base::Catalogue::decode(&app6[..base::SIZE]).is_ok());
    assert!(matches!(
        catalogue::Catalogue::decode(&app6),
        Err(catalogue::Error::Base(base::Error::Profile))
    ));
    let mut app_b6 = full;
    app_b6[catalogue::BASE_SIZE + 160 + 137] = 6;
    assert!(matches!(
        catalogue::Catalogue::decode(&app_b6),
        Err(catalogue::Error::Image)
    ));
}

#[test]
fn only_four_file_routes_have_aggregate_bounds_and_network_children_stay_tight() {
    for channel in graph::CHANNELS {
        let expected = match channel {
            graph::Channel::NotesRead
            | graph::Channel::NotesWrite
            | graph::Channel::PrivateRead
            | graph::Channel::PrivateWrite => 8192,
            _ => 1024,
        };
        assert_eq!(channel.session_rpc_ticks(), expected);
        if channel.wire_index() < 15 {
            assert_eq!(
                channel.session_rpc_ticks(),
                root_v2::graph::CHANNELS[channel.wire_index()].session_rpc_ticks()
            );
        }
    }
    assert_eq!(FILE_TRANSACTION_MAX_TICKS, 8192);
    assert_eq!((CPU_QUOTA, CPU_PERIOD, ROOT_CPU_QUOTA), (64, 256, 256));
}
#[test]
fn catalogue_has_full_v4_measurement_and_actor_specific_frame_caps() {
    let bytes = catalogue_bytes();
    let value = catalogue::Catalogue::decode(&bytes).unwrap();
    assert_eq!(bytes.len(), 4096);
    assert_eq!(value.base().bytes(), &base_bytes());
    assert_eq!(value.root_abi(), ABI);
    assert_eq!(value.net_driver().limits, [16384, 32, 1, 1]);
    assert_eq!(value.net_service().limits, [16384, 64, 1, 1]);
    assert_eq!(value.network_policy().dns_name, "example.org");
    assert_eq!(value.network_policy().allowed_ipv4, [10, 0, 2, 2]);
    assert_eq!(value.device().mac, catalogue::REFERENCE_MAC);
    assert!(native::catalogue::Catalogue::decode(&bytes).is_err());
    assert!(base::Catalogue::decode(&bytes).is_err());
    assert!(catalogue::Catalogue::decode(value.base().bytes()).is_err());
    let (a, b) = value.measurement_parts();
    assert_eq!(a.len() + 32 + b.len(), 4096);
    assert_eq!(a.len(), catalogue::MEASUREMENT_OFFSET);
}
#[test]
fn actor_profile_device_timer_policy_and_reserved_mutations_fail_closed() {
    let bytes = catalogue_bytes();
    for relative in [14, 15, 514, 519, 2536, 2559] {
        let mut b = bytes;
        b[catalogue::BASE_SIZE + relative] = 1;
        assert!(catalogue::Catalogue::decode(&b).is_err());
    }
    for relative in [
        520,
        520 + 72,
        520 + 104 + 8,
        520 + 137,
        696,
        696 + 104 + 8,
        696 + 137,
    ] {
        let mut b = bytes;
        b[catalogue::BASE_SIZE + relative] ^= 1;
        assert!(catalogue::Catalogue::decode(&b).is_err());
    }
    for relative in [
        872,
        872 + 16,
        872 + 20,
        872 + 24,
        872 + 30,
        872 + 96,
        1000 + 8,
        1000 + 16,
        1000 + 32,
        1000 + 63,
        1064 + 8,
        1064 + 16,
        1064 + 96,
        1192 + 13,
        1192 + 24,
        1192 + 319,
        1512 + 16,
        1512 + 1023,
    ] {
        let mut b = bytes;
        b[catalogue::BASE_SIZE + relative] ^= 0x80;
        assert!(
            catalogue::Catalogue::decode(&b).is_err(),
            "relative={relative}"
        );
    }
    let mut b = bytes;
    b[catalogue::BASE_SIZE + 1192 + 16] = 224;
    assert!(matches!(
        catalogue::Catalogue::decode(&b),
        Err(catalogue::Error::Policy)
    ));
    let mut b = bytes;
    b[catalogue::BASE_SIZE + 1192 + 20..catalogue::BASE_SIZE + 1192 + 22].fill(0);
    assert!(matches!(
        catalogue::Catalogue::decode(&b),
        Err(catalogue::Error::Policy)
    ));
    let mut b = bytes;
    b[catalogue::BASE_SIZE + 872 + 32..catalogue::BASE_SIZE + 872 + 64].fill(0);
    assert!(matches!(
        catalogue::Catalogue::decode(&b),
        Err(catalogue::Error::Device)
    ));
    let mut b = bytes;
    b[catalogue::BOOT_MODE_OFFSET..catalogue::BOOT_MODE_OFFSET + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    assert!(matches!(
        catalogue::Catalogue::decode(&b),
        Err(catalogue::Error::Mode)
    ));
}
#[test]
fn only_mode_and_measurement_are_excluded_from_cohort_recipe() {
    let a = catalogue_bytes();
    let mut b = a;
    b[catalogue::BOOT_MODE_OFFSET..catalogue::BOOT_MODE_OFFSET + 2]
        .copy_from_slice(&2u16.to_le_bytes());
    b[catalogue::MEASUREMENT_OFFSET..catalogue::MEASUREMENT_OFFSET + 32].fill(99);
    let av = catalogue::Catalogue::decode(&a).unwrap();
    let bv = catalogue::Catalogue::decode(&b).unwrap();
    assert_eq!(av.cohort_parts(), bv.cohort_parts());
    assert_ne!(av.measurement_parts(), bv.measurement_parts());
    b[catalogue::BASE_SIZE + 872 + 32] ^= 1;
    let changed = catalogue::Catalogue::decode(&b).unwrap();
    assert_ne!(av.cohort_parts(), changed.cohort_parts());
}
#[test]
fn package_lengths_and_complete_input_extents_are_checked_without_rounding_overflow() {
    for (bytes, pages) in [(1, 1), (4096, 1), (4097, 2), (PACKAGE_MAX_BYTES, 63)] {
        assert_eq!(catalogue::package_pages(bytes), Some(pages));
    }
    for bytes in [0, PACKAGE_MAX_BYTES + 1, u64::MAX] {
        assert_eq!(catalogue::package_pages(bytes), None);
    }
    let startup = startup();
    for n in 0..SIZE {
        assert!(Bootstrap::parse(&startup[..n]).is_err());
    }
    let cat = catalogue_bytes();
    for n in 0..catalogue::SIZE {
        assert!(catalogue::Catalogue::decode(&cat[..n]).is_err());
    }
}
#[test]
fn arbitrary_single_byte_catalogue_and_startup_changes_are_total_parsers() {
    let startup = startup();
    for n in 0..SIZE {
        let mut b = startup;
        b[n] ^= 0xa5;
        let _ = FullGraph::parse(&b);
    }
    let cat = catalogue_bytes();
    for n in 0..catalogue::SIZE {
        let mut b = cat;
        b[n] ^= 0xa5;
        let _ = catalogue::Catalogue::decode(&b);
    }
}

#[test]
fn full_graph_requires_exact_ancestor_capacity_and_binds_single_held_replacement() {
    let bytes = startup();
    for (field, value) in [(56usize, 8u64), (64, 9), (56, 11), (40, 65537), (48, 513)] {
        let mut changed = bytes;
        changed[field..field + 8].copy_from_slice(&value.to_le_bytes());
        assert!(Bootstrap::parse(&changed).is_ok());
        assert!(matches!(FullGraph::parse(&changed), Err(Error::Limits)));
    }
    let layout = layout_description();
    assert_eq!(u64::from_le_bytes(layout[360..368].try_into().unwrap()), 10);
    assert_eq!(u64::from_le_bytes(layout[368..376].try_into().unwrap()), 10);
    assert_eq!(u64::from_le_bytes(layout[376..384].try_into().unwrap()), 1);
}

#[test]
fn trusted_job_templates_bind_limits_and_each_child_without_changing_legacy_profile() {
    let layout = layout_description();
    assert_eq!(&layout[848..856], b"EVJTPL04");
    assert_eq!(word(&layout, 856), 2);
    for (id, limits) in JOB_TEMPLATE_LIMITS.into_iter().enumerate() {
        let at = 864 + id * 40;
        assert_eq!(word(&layout, at), id as u64);
        for (resource, limit) in limits.into_iter().enumerate() {
            assert_eq!(word(&layout, at + 8 + resource * 8), limit);
        }
    }
    let description = graph::description();
    let first = 32 + graph::GRANT_COUNTS.iter().sum::<usize>() * 16 + graph::CHANNELS.len() * 8;
    for child in graph::CHILDREN {
        let id = u64::from(child == graph::Child::NetService);
        assert_eq!(child.job_template(), id);
        assert_eq!(child.limits(), JOB_TEMPLATE_LIMITS[id as usize]);
        let at = first + child.index() * 48;
        assert_eq!(word(&description, at), child.index() as u64);
        assert_eq!(word(&description, at + 8), id);
        for (resource, limit) in child.limits().into_iter().enumerate() {
            assert_eq!(word(&description, at + 16 + resource * 8), limit);
        }
    }
    assert_eq!(first + graph::CHILDREN.len() * 48, 1352);
    let catalogue = catalogue_bytes();
    // The table is inside the authoritative measured V4 layout, not a hint
    // alongside a legacy catalogue that could still admit another template.
    for offset in [848, 856, 864, 872, 880, 904, 912, 920] {
        let mut changed = catalogue;
        changed[1536 + 1512 + offset] ^= 1;
        assert_eq!(
            catalogue::Catalogue::decode(&changed).err(),
            Some(catalogue::Error::Layout)
        );
    }
}

#[test]
fn rtc_is_one_exact_root_only_nondelegating_role_and_measured_elapsed_policy() {
    let bytes = startup();
    let graph = FullGraph::parse(&bytes).unwrap();
    let rtc = graph
        .grants()
        .find(|g| g.selector == Role::RtcPorts.selector())
        .unwrap();
    assert_eq!((rtc.kind, rtc.rights), (7, 3));
    for child in graph::CHILDREN {
        assert!(graph::grants(child).all(|g| g.source != graph::Source::Root(Role::RtcPorts)));
    }
    let good = startup();
    let at = HEADER + 28 * GRANT_BYTES;
    for (offset, value) in [(at + 16, 1), (at + 18, 1), (at + 18, 7), (at + 18, 227)] {
        let mut changed = good;
        changed[offset] = value;
        assert!(FullGraph::parse(&changed).is_err());
    }
    let mut missing = good;
    missing[136] = 28;
    missing[at..at + GRANT_BYTES].fill(0);
    assert!(Bootstrap::parse(&missing).is_ok());
    assert!(FullGraph::parse(&missing).is_err());
    let layout = layout_description();
    assert_eq!(&layout[976..984], b"EVRTC004");
    for (at, value) in [
        (984, 0x70),
        (992, 0x71),
        (1000, 0x32),
        (1008, 512),
        (1016, 4),
    ] {
        assert_eq!(word(&layout, at), value);
        let mut c = catalogue_bytes();
        c[1536 + 1512 + at] ^= 1;
        assert_eq!(
            catalogue::Catalogue::decode(&c).err(),
            Some(catalogue::Error::Layout)
        );
    }
}

#[test]
fn old_224_abi_and_each_capacity_word_are_rejected_as_current_catalogue() {
    // Captured actual joined17 Root ABI before this private refinement.
    const OLD_ABI: [u8; 32] = [
        0x9e, 0x90, 0x06, 0xbc, 0xb7, 0xdc, 0xf8, 0xbd, 0x61, 0xe7, 0xa4, 0xff, 0xcb, 0x6f, 0x32,
        0x1c, 0x3d, 0xe9, 0xd9, 0x33, 0x53, 0xc5, 0xce, 0x0e, 0x38, 0x29, 0xee, 0x6c, 0x89, 0x42,
        0x65, 0x50,
    ];
    let current = catalogue_bytes();
    assert!(catalogue::Catalogue::decode(&current).is_ok());
    let mut old = current;
    old[catalogue::BASE_SIZE + 16..catalogue::BASE_SIZE + 48].copy_from_slice(&OLD_ABI);
    assert!(matches!(
        catalogue::Catalogue::decode(&old),
        Err(catalogue::Error::Abi)
    ));
    let layout = catalogue::BASE_SIZE + 1512;
    // Keep the current primary ABI and all other bytes: each old capacity
    // field must fail the actual full layout check independently.
    for (offset, value) in [(952, 224u64), (960, 228), (968, 230)] {
        let mut old = current;
        old[layout + offset..layout + offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(
            catalogue::Catalogue::decode(&old),
            Err(catalogue::Error::Layout)
        ));
    }
    let mut old = current;
    old[layout + 16..layout + 48].copy_from_slice(&OLD_ABI);
    for (offset, value) in [(952, 224u64), (960, 228), (968, 230)] {
        old[layout + offset..layout + offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    assert!(matches!(
        catalogue::Catalogue::decode(&old),
        Err(catalogue::Error::Layout)
    ));
}
