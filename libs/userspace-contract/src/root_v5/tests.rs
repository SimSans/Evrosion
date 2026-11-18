extern crate std;
mod external_ingress;
use super::*;
use graph::{Channel, Child, DeliveryMode, ImageSlot, Sender, Source};
fn context(limits: [u64; 4]) -> Context {
    Context {
        epoch: 1,
        incarnation: 2,
        process: 3,
        limits,
        manifest: [4; 32],
        authority: [5; 32],
    }
}
fn startup() -> [u8; SIZE] {
    encode_full_graph(
        context(resources::ROOT_LIMITS),
        core::array::from_fn(|i| 100 + i as u64),
    )
    .unwrap()
}
fn description() -> catalogue::Description<'static> {
    let images = core::array::from_fn(|i| {
        let actor = graph::IMAGES[i].representative();
        catalogue::Image {
            image: [10 + i as u8; 32],
            descriptor: [30 + i as u8; 32],
            abi: child::abi(actor),
            limits: actor.limits(),
            role_shape: [50 + i as u8; 32],
        }
    });
    let packages = core::array::from_fn(|i| {
        let kind = catalogue::PACKAGES[i];
        catalogue::Package {
            app_id: [if i == 3 { 2 } else { i as u8 + 1 }; 16],
            digest: [70 + i as u8; 32],
            build: [80 + i as u8; 32],
            image: if i == 3 {
                [99; 32]
            } else {
                images[kind.image().index()].image
            },
            bytes: 4096 + i as u64,
            bank: if i == 3 {
                catalogue::PackageBank::Candidate
            } else {
                catalogue::PackageBank::Current
            },
            offset: if i == 3 { 0 } else { (i * 8192) as u32 },
        }
    });
    catalogue::Description {
        root_image: [1; 32],
        kernel_input: [2; 32],
        graph_measurement: [3; 32],
        layout_measurement: [4; 32],
        measurement: [5; 32],
        boot_mode: catalogue::BootMode::SystemManaged,
        restart_attempts: 3,
        restart_window: 60000,
        images,
        instance_bindings: core::array::from_fn(|i| [100 + i as u8; 32]),
        packages,
        device: catalogue::DeviceWitness {
            mac: catalogue::REFERENCE_MAC,
            model_source_sha256: [7; 32],
            emulator_binary_sha256: [8; 32],
        },
        network: catalogue::NetworkPolicy {
            allowed_ipv4: [10, 0, 2, 2],
            remote_port: 8080,
            local_port: 49152,
            dns_name: "example.org",
        },
    }
}
fn catalogue_bytes() -> [u8; catalogue::SIZE] {
    catalogue::encode(description()).unwrap()
}

#[test]
fn package_bank_locations_bind_exact_lengths_without_overwriting_package_hashes() {
    use catalogue::{
        PACKAGE_AT, PACKAGE_BYTES, PACKAGES, PLACEMENT_AT, PLACEMENT_BYTES, PackageBank,
        PackageKind,
    };
    let original = description();
    let bytes = catalogue::encode(description()).unwrap();
    let parsed = catalogue::Catalogue::decode(&bytes).unwrap();
    for kind in PACKAGES {
        let input = original.packages[kind.index()];
        let at = PACKAGE_AT + kind.index() * PACKAGE_BYTES;
        assert_eq!(&bytes[at + 88..at + 120], &input.image);
        assert_eq!(word(&bytes, at + 120), input.bytes);
        assert_eq!(parsed.package(kind), input);
        let location = PLACEMENT_AT + kind.index() * PLACEMENT_BYTES;
        assert_eq!(bytes[location + 2], input.bank as u8);
        assert_eq!(bytes[location + 3], 1);
        assert_eq!(word(&bytes, location + 8), input.bytes);
    }
    for mutation in [0, 1, 2, 3, 4] {
        let mut bad = description();
        let editor = &mut bad.packages[PackageKind::Editor.index()];
        match mutation {
            0 => editor.bank = PackageBank::Candidate,
            1 => editor.offset = 1,
            2 => editor.offset = 0,
            3 => editor.offset = resources::PACKAGE_CURRENT_BYTES as u32,
            4 => editor.bytes = u64::MAX,
            _ => unreachable!(),
        }
        assert!(matches!(catalogue::encode(bad), Err(Error::Package)));
    }
    for (slot, delta) in [(2usize, 255u8), (3, 0), (8, 1)] {
        let mut bad = bytes;
        let at = PLACEMENT_AT + PackageKind::EditorCandidate.index() * PLACEMENT_BYTES + slot;
        bad[at] = if slot == 8 { bad[at] ^ delta } else { delta };
        assert!(catalogue::Catalogue::decode(&bad).is_err());
    }
    let mut missing = bytes;
    missing[PLACEMENT_AT..catalogue::PLACEMENT_END].fill(0);
    assert!(catalogue::Catalogue::decode(&missing).is_err());
    let mut boundary = description();
    boundary.packages[3].offset = 0;
    boundary.packages[3].bytes = resources::PACKAGE_MAX_BYTES;
    assert!(catalogue::encode(boundary).is_ok());
    let mut crossing = description();
    crossing.packages[3].offset = resources::PACKAGE_MAX_BYTES as u32 - 16;
    crossing.packages[3].bytes = 17;
    assert!(matches!(catalogue::encode(crossing), Err(Error::Package)));
}

#[test]
fn current_bank_growth_preserves_candidate_and_individual_bounds() {
    use catalogue::PackageBank;
    assert_eq!(
        (
            PackageBank::Current.first_page(),
            PackageBank::Current.pages(),
            PackageBank::Current.capacity_bytes()
        ),
        (368, 79, 323584)
    );
    assert_eq!(
        (
            PackageBank::Candidate.first_page(),
            PackageBank::Candidate.pages(),
            PackageBank::Candidate.capacity_bytes()
        ),
        (304, 63, 258048)
    );
    assert_eq!(resources::PACKAGE_MAX_BYTES, 258048);
    let mut expanded = description();
    expanded.packages[2].offset = resources::PACKAGE_CANDIDATE_BYTES as u32;
    let bytes = catalogue::encode(expanded).unwrap();
    let decoded = catalogue::Catalogue::decode(&bytes).unwrap();
    assert_eq!(
        decoded.package(catalogue::PackageKind::Inspector).offset,
        258048
    );
    let mut boundary = description();
    boundary.packages[2].offset = resources::PACKAGE_CURRENT_BYTES as u32 - 16;
    boundary.packages[2].bytes = 16;
    assert!(catalogue::encode(boundary).is_ok());
    let mut crossing = description();
    crossing.packages[2].offset = resources::PACKAGE_CURRENT_BYTES as u32 - 16;
    crossing.packages[2].bytes = 17;
    assert!(matches!(catalogue::encode(crossing), Err(Error::Package)));
    let mut oversized = description();
    oversized.packages[2].bytes = resources::PACKAGE_MAX_BYTES + 1;
    assert!(matches!(catalogue::encode(oversized), Err(Error::Package)));
}

#[test]
fn independently_typed_v5_records_do_not_relabel_any_legacy_bootstrap() {
    assert_eq!(
        (VERSION, PROFILE, SIZE, CURRENT_GRANTS, MAX_GRANTS),
        (5, 5, 1104, 37, 40)
    );
    let bytes = startup();
    let parsed = FullGraph::parse(&bytes).unwrap();
    assert_eq!(parsed.handle(Role::ProtectedSurface), 131);
    assert_eq!(parsed.context().limits, resources::ROOT_LIMITS);
    assert!(crate::Bootstrap::parse(&bytes).is_err());
    assert!(crate::root_v2::Bootstrap::parse(&bytes).is_err());
    assert!(crate::root_v4::Bootstrap::parse(&bytes).is_err());
    let old = crate::root_v4::encode_full_graph(
        context(crate::root_v4::ROOT_LIMITS),
        core::array::from_fn(|i| 100 + i as u64),
    )
    .unwrap();
    assert!(Bootstrap::parse(&old).is_err());
    assert_ne!(ABI, crate::root_v4::ABI);
    assert_ne!(ABI, crate::root_v2::native::ABI);
    assert_eq!(crate::SIZE, 336);
    assert_eq!(crate::MAX_GRANTS, 8);
    assert_eq!(crate::root_v4::CURRENT_GRANTS, 29);
}
#[test]
fn root_identity_grant_alias_reserved_and_role_changes_are_rejected() {
    let original = startup();
    for (mutated, expected) in [
        (16, Error::Identity),
        (HEADER + 17, Error::Reserved),
        (SIZE - 1, Error::Reserved),
    ] {
        let mut bad = original;
        if mutated == 16 {
            bad[16..24].fill(0);
        } else {
            bad[mutated] = 1;
        }
        assert!(matches!(Bootstrap::parse(&bad),Err(error)if error==expected));
    }
    let mut alias = original;
    let handle = alias[HEADER + 8..HEADER + 16].to_vec();
    alias[HEADER + GRANT_BYTES + 8..HEADER + GRANT_BYTES + 16].copy_from_slice(&handle);
    assert!(matches!(Bootstrap::parse(&alias), Err(Error::Alias)));
    let mut changed = original;
    changed[HEADER + 16] = 7;
    assert!(Bootstrap::parse(&changed).is_ok());
    assert!(matches!(FullGraph::parse(&changed), Err(Error::Roles)));
    let fewer: std::vec::Vec<_> = FullGraph::parse(&original)
        .unwrap()
        .grants()
        .take(36)
        .collect();
    let fewer = encode(context(resources::ROOT_LIMITS), &fewer).unwrap();
    assert!(matches!(FullGraph::parse(&fewer), Err(Error::Roles)));
}
#[test]
fn workspace_display_use_strict_additive16_record_other_images_stay_v1() {
    assert_eq!(child::SIZE, 528);
    for actor in [Child::Workspace, Child::Display] {
        let handles: std::vec::Vec<_> = (0..graph::grants(actor).len())
            .map(|i| 100 + i as u64)
            .collect();
        let b = child::encode_profile(actor, context(actor.limits()), &handles).unwrap();
        let p = child::Profile::parse(actor, &b).unwrap();
        assert_eq!(p.handle(handles.len() as u64), handles.last().copied());
        assert_eq!(p.handle(17), None);
        assert!(crate::Bootstrap::parse(&b).is_err());
        assert!(Bootstrap::parse(&b).is_err());
    }
    for actor in [
        Child::Block,
        Child::Input,
        Child::NetDriver,
        Child::NetService,
        Child::EditorOne,
        Child::EditorTwo,
    ] {
        assert_eq!(child::startup_size(actor), 336);
        assert_eq!(child::abi(actor), crate::ABI);
        assert!(matches!(
            child::encode_profile(actor, context(actor.limits()), &[]),
            Err(Error::Profile)
        ));
    }
    let mut b = child::encode_profile(
        Child::Workspace,
        context(Child::Workspace.limits()),
        &(100..116).collect::<std::vec::Vec<_>>(),
    )
    .unwrap();
    b[HEADER + 15 * GRANT_BYTES + 18..HEADER + 15 * GRANT_BYTES + 20]
        .copy_from_slice(&8u16.to_le_bytes());
    assert!(child::Bootstrap::parse(&b).is_ok());
    assert!(matches!(
        child::Profile::parse(Child::Workspace, &b),
        Err(Error::Roles)
    ));
}
#[test]
fn graph_keeps_root_control_unforgeable_and_shared_routes_caller_bound() {
    assert_eq!(
        graph::CHANNELS
            .iter()
            .filter(|channel| channel.delivery() == DeliveryMode::Rpc)
            .count(),
        14
    );
    assert_eq!(
        graph::CHANNELS
            .iter()
            .filter(|channel| channel.delivery() == DeliveryMode::Async)
            .count(),
        5
    );
    assert_eq!(
        graph::CHANNELS
            .iter()
            .filter(|channel| channel.delivery() == DeliveryMode::Selected)
            .count(),
        4
    );
    assert_eq!(Channel::from_wire_index(graph::ROOT_EVENTS_WIRE), None);
    for channel in [Channel::RootWorkspaceControl, Channel::DisplayControl] {
        assert!(channel.allows(Sender::Root));
        for actor in graph::CHILDREN {
            assert!(!channel.allows(Sender::Child(actor)));
            assert!(!graph::grants(actor).any(|grant|grant.source==Source::Endpoint(channel)&&grant.rights&8!=0));
        }
    }
    let ws: std::vec::Vec<_> = graph::grants(Child::Workspace).collect();
    assert_eq!(ws.len(), 16);
    assert_eq!(ws[9].source, Source::Endpoint(Channel::WorkspaceNamespace));
    assert_eq!(
        ws[15].source,
        Source::Endpoint(Channel::RootWorkspaceControl)
    );
    let display: std::vec::Vec<_> = graph::grants(Child::Display).collect();
    assert_eq!(display[9].source, Source::Endpoint(Channel::DisplayControl));
    assert_eq!(display[9].rights, 272);
}
#[test]
fn editor_instances_share_code_shape_but_never_surface_frame_control_or_inbox() {
    assert_eq!(Child::EditorOne.image(), Child::EditorTwo.image());
    assert_ne!(Child::EditorOne.instance(), Child::EditorTwo.instance());
    assert_ne!(Child::EditorOne.surface(), Child::EditorTwo.surface());
    assert_ne!(Child::EditorOne.frame(), Child::EditorTwo.frame());
    assert_ne!(Child::EditorOne.control(), Child::EditorTwo.control());
    assert_ne!(Child::EditorOne.inbox(), Child::EditorTwo.inbox());
    let one: std::vec::Vec<_> = graph::grants(Child::EditorOne).collect();
    let two: std::vec::Vec<_> = graph::grants(Child::EditorTwo).collect();
    assert_eq!(one.len(), 6);
    for (a, b) in one.iter().zip(two) {
        assert_eq!((a.kind, a.rights), (b.kind, b.rights));
    }
    for actor in [
        Child::Files,
        Child::EditorOne,
        Child::EditorTwo,
        Child::Inspector,
    ] {
        for grant in graph::grants(actor) {
            assert_eq!(
                grant.rights & (32 | 64 | 128 | 256),
                if grant.kind == 2 && grant.rights & 16 != 0 {
                    256
                } else {
                    0
                }
            );
            assert!(!matches!(
                grant.source,
                Source::Root(
                    Role::CreatorJob
                        | Role::Display
                        | Role::ProtectedSurface
                        | Role::AtaPorts
                        | Role::NicPorts
                )
            ));
        }
    }
}
#[test]
fn census_is_derived_lower_bound_and_not_a_runtime_admission_result() {
    let count: usize = graph::CHILDREN
        .into_iter()
        .map(|actor| graph::grants(actor).len())
        .sum();
    assert_eq!(count, 75);
    assert_eq!(
        CURRENT_GRANTS + graph::CHANNELS.len() + 2 * graph::CHILDREN.len(),
        resources::BASELINE_OBJECT_LOWER_BOUND
    );
    assert_eq!(
        3 * CURRENT_GRANTS + graph::CHANNELS.len() + 2 * graph::CHILDREN.len() + 2 * count,
        resources::STEADY_LINEAGE_LOWER_BOUND
    );
    assert_eq!(
        3 + graph::CHANNELS.len() + 2 * graph::CHILDREN.len() + 1,
        resources::STEADY_SPACE_LOWER_BOUND
    );
    assert_eq!(
        (
            resources::STEADY_JOBS,
            resources::STEADY_PROCESSES,
            resources::STEADY_THREADS
        ),
        (13, 12, 12)
    );
    assert_eq!(
        (
            resources::HELD_JOBS,
            resources::HELD_PROCESSES,
            resources::HELD_THREADS
        ),
        (14, 13, 13)
    );
    assert_eq!(resources::proposed_census()[8..32], [0; 24]);
}
fn disjoint(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 + a.1 <= b.0 || b.0 + b.1 <= a.0
}
#[test]
fn declared_mapping_ranges_guards_and_editor_bss_are_disjoint() {
    let ranges = [
        (0, 240),
        (
            resources::ROOT_STACK_FIRST_PAGE,
            resources::ROOT_STACK_PAGES,
        ),
        (304, 63),
        (368, 79),
        (448, 51),
        (500, 3),
        (503, 2),
        (505, 1),
        (508, 1),
        (509, 1),
    ];
    for (i, a) in ranges.into_iter().enumerate() {
        assert!(a.0 + a.1 <= 512);
        for b in ranges[..i].iter().copied() {
            assert!(disjoint(a, b));
        }
    }
    for guard in [255, 264, 303, 367, 447, 499, 510] {
        assert!(
            ranges
                .iter()
                .all(|range| !(range.0..range.0 + range.1).contains(&guard))
        );
    }
    let editor = [(64, 256), (480, 8), (384, 63), (506, 2), (509, 1)];
    for (i, a) in editor.into_iter().enumerate() {
        for b in editor[..i].iter().copied() {
            assert!(disjoint(a, b));
        }
    }
    for (i, (_, first, pages)) in resources::DISPLAY_SURFACES.into_iter().enumerate() {
        assert!(first + pages <= 435 || first + pages <= 383);
        for (_, other, len) in resources::DISPLAY_SURFACES[..i].iter().copied() {
            assert!(disjoint((first, pages), (other, len)));
        }
    }
    assert_eq!(resources::max_loader_frames(ImageSlot::Display), 88);
    assert_eq!(resources::max_loader_frames(ImageSlot::Editor), 390);
    assert!(
        resources::ROOT_PROTECTED_PIXEL_BYTES + surface::ROOT_PIXEL_OFFSET
            <= resources::PROTECTED_PAGES as usize * 4096
    );
}
#[test]
fn catalogue_joins_independent_images_instances_packages_and_exact_policy_bytes() {
    let b = catalogue_bytes();
    let c = catalogue::Catalogue::decode(&b).unwrap();
    assert_eq!(c.boot_mode(), catalogue::BootMode::SystemManaged);
    assert_eq!(c.image(ImageSlot::Workspace).abi, child::ABI);
    assert_eq!(c.image(ImageSlot::Block).abi, crate::ABI);
    assert_eq!(c.image(ImageSlot::Editor).limits, [1_000_000, 512, 1, 1]);
    assert_ne!(
        c.instance_binding(Child::EditorOne),
        c.instance_binding(Child::EditorTwo)
    );
    assert_eq!(
        c.package(catalogue::PackageKind::Editor).app_id,
        c.package(catalogue::PackageKind::EditorCandidate).app_id
    );
    assert!(crate::root_v4::catalogue::Catalogue::decode(&b).is_err());
    let first = catalogue::INSTANCE_AT + Child::EditorOne.index() * catalogue::INSTANCE_BYTES + 32;
    let second = catalogue::INSTANCE_AT + Child::EditorTwo.index() * catalogue::INSTANCE_BYTES + 32;
    let mut alias = b;
    let binding = alias[first..first + 32].to_vec();
    alias[second..second + 32].copy_from_slice(&binding);
    assert!(matches!(
        catalogue::Catalogue::decode(&alias),
        Err(Error::Alias)
    ));
}
#[test]
fn catalogue_malformed_images_network_policy_resource_tables_and_tail_refuse() {
    let b = catalogue_bytes();
    for (offset, error) in [
        (catalogue::IMAGE_AT + 72, Error::Image),
        (catalogue::GRAPH_AT + 8, Error::Layout),
        (catalogue::LAYOUT_AT + 80, Error::Layout),
        (catalogue::CENSUS_AT + 8, Error::Layout),
        (catalogue::SIZE - 1, Error::Reserved),
    ] {
        let mut changed = b;
        changed[offset] ^= 1;
        assert!(matches!(catalogue::Catalogue::decode(&changed),Err(actual)if actual==error));
    }
    let mut bad = b;
    bad[catalogue::POLICY_AT + 12] = 254;
    assert!(matches!(
        catalogue::Catalogue::decode(&bad),
        Err(Error::Policy)
    ));
    let mut bad = description();
    bad.network.dns_name = "Example.org";
    assert!(matches!(catalogue::encode(bad), Err(Error::Policy)));
    let mut bad = description();
    bad.packages[0].bytes = resources::PACKAGE_MAX_BYTES + 1;
    assert!(matches!(catalogue::encode(bad), Err(Error::Package)));
}
fn surface_header() -> surface::Header {
    surface::Header {
        producer: surface::Producer::Application,
        instance: 2,
        process: 10,
        thread: 11,
        incarnation: 12,
        surface_object: 13,
        surface_generation: 14,
        frame: 1,
        view_revision: 1,
        model_revision: 1,
        width: 320,
        height: 180,
        stride_bytes: 1280,
        payload_bytes: 230400,
        mapping_epoch: 1,
        protected_scope_nonce: 0,
    }
}
#[test]
fn new_surface_header_has_variable_geometry_but_cannot_claim_owner_authority() {
    let h = surface_header();
    assert_eq!(surface::Header::parse(&h.encode().unwrap()), Ok(h));
    assert_eq!(h.pixel_offset(), 256);
    let mut bad = h;
    bad.width = 321;
    assert_eq!(bad.encode(), Err(Error::Layout));
    let mut bad = h;
    bad.payload_bytes += 4;
    assert_eq!(bad.encode(), Err(Error::Layout));
    let mut b = h.encode().unwrap();
    b[..8].copy_from_slice(b"EVSURF01");
    assert_eq!(surface::Header::parse(&b), Err(Error::Version));
    let registration = surface::Registration {
        sequence: 1,
        source_role: Role::EditorOneSurface,
        producer: h.producer,
        instance: 2,
        process: h.process,
        thread: h.thread,
        incarnation: h.incarnation,
        surface_object: h.surface_object,
        surface_generation: h.surface_generation,
        mapping_epoch: 1,
    };
    assert_eq!(
        surface::Registration::parse(&registration.encode().unwrap()),
        Ok(registration)
    );
    assert!(registration.matches(h, 10, 11, 12));
    assert!(!registration.matches(h, 99, 11, 12));
    let mut forged = h;
    forged.producer = surface::Producer::ProtectedRoot;
    forged.instance = 0;
    forged.width = 640;
    forged.height = 80;
    forged.stride_bytes = 2560;
    forged.payload_bytes = 204800;
    assert!(forged.encode().is_ok());
    assert!(!registration.matches(forged, 10, 11, 12));
    assert_eq!(forged.pixel_offset(), 512);
    let mut changed = registration;
    changed.source_role = Role::ProtectedSurface;
    assert_eq!(changed.encode(), Err(Error::Profile));
}
#[test]
fn manifest_version_source_roles_and_new_origin_contract_are_explicit() {
    let b = manifest_profile(ManifestInputs {
        root_image: [1; 32],
        catalogue: [2; 32],
        authority: [3; 32],
        restart_attempts: 3,
        restart_window: 60000,
    })
    .unwrap();
    assert_eq!(&b[..8], b"EVBM0005");
    assert_eq!(&b[48..80], &ABI);
    assert_eq!(b[160], 37);
    assert_eq!(word(&b, 80), 4_000_000);
    assert_eq!(resources::BOOT_LIMITS[0], 8_000_000);
    assert!(
        resources::JOB_TEMPLATE_LIMITS
            .iter()
            .all(|limits| limits[0] == 1_000_000)
    );
    assert_eq!(crate::syscall::SERVING_ORIGIN_V1, 0x0000000100080001);
    assert_eq!(crate::syscall::PROCESS_JOB_INFO_V1, 0x0000000100090003);
    let l = resources::layout_description();
    assert_eq!(word(&l, 1704), crate::syscall::SERVING_ORIGIN_V1);
    assert_eq!(&l[1712..1744], &crate::syscall::SERVING_ORIGIN_ABI);
}
