//! Trusted finite resource bindings, not generation or health policy.
use super::*;
use ev_kernel::{events::Channel as Events, scheduler::JobId};
use ev_userspace_contract::generation::{Catalogue, HEALTH_DESCRIPTION};
use sha2::{Digest as _, Sha256};
pub(super) struct Resources {
    pub catalogue: Catalogue,
    pub digest: [u8; 32],
    pub object: MemoryObject,
    pub cap: Handle,
    pub alias: *mut u8,
    pub job_cap: Handle,
    pub job: JobId,
    pub images: [Handle; 2],
    pub image_objects: [usize; 2],
    pub max_frames: u64,
    pub event_cap: Handle,
    pub events: Events,
    pub uart_cap: Option<Handle>,
    pub uart_object: Option<usize>,
}
struct Assets {
    client: &'static [u8],
    client_sha: [u8; 32],
    a: &'static [u8],
    b: &'static [u8],
    catalogue: &'static [u8],
    catalogue_sha: [u8; 32],
}
#[cfg(feature = "test-m3-generation")]
fn generation_assets() -> Assets {
    Assets {
        client: bundle::M3_GENERATION_CLIENT_IMAGE,
        client_sha: bundle::M3_GENERATION_CLIENT_SHA,
        a: bundle::GENERATION_GOOD_IMAGE,
        b: bundle::GENERATION_BAD_IMAGE,
        catalogue: bundle::M3_GENERATION_CATALOGUE,
        catalogue_sha: bundle::M3_GENERATION_CATALOGUE_SHA,
    }
}
#[cfg(not(feature = "test-m3-generation"))]
fn generation_assets() -> Assets {
    panic!("generation assets were not compiled")
}
#[cfg(feature = "test-m3-owner")]
fn owner_assets() -> Assets {
    Assets {
        client: bundle::M3_OWNER_CLIENT_IMAGE,
        client_sha: bundle::M3_OWNER_CLIENT_SHA,
        a: bundle::GENERATION_GOOD_IMAGE,
        b: bundle::GENERATION_BAD_IMAGE,
        catalogue: bundle::M3_OWNER_CATALOGUE,
        catalogue_sha: bundle::M3_OWNER_CATALOGUE_SHA,
    }
}
#[cfg(feature = "test-m3-progress")]
fn progress_assets() -> Assets {
    Assets {
        client: bundle::M3_PROGRESS_CLIENT_IMAGE,
        client_sha: bundle::M3_PROGRESS_CLIENT_SHA,
        a: bundle::GENERATION_GOOD_IMAGE,
        b: bundle::GENERATION_SILENT_IMAGE,
        catalogue: bundle::M3_PROGRESS_CATALOGUE,
        catalogue_sha: bundle::M3_PROGRESS_CATALOGUE_SHA,
    }
}
#[cfg(not(feature = "test-m3-progress"))]
fn progress_assets() -> Assets {
    panic!("Progress assets were not compiled")
}
#[cfg(not(feature = "test-m3-owner"))]
fn owner_assets() -> Assets {
    panic!("Owner assets were not compiled")
}
fn assets(profile: Profile) -> Assets {
    match profile {
        Profile::Owner => owner_assets(),
        Profile::Progress => progress_assets(),
        Profile::Generation => generation_assets(),
        _ => panic!("not a measured catalogue profile"),
    }
}
fn build_identity() -> [u8; 32] {
    let bytes = crate::BUILD_ID.as_bytes();
    assert_eq!(bytes.len(), 64, "recorded generation build input");
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("build input must be canonical lowercasehex"),
    };
    core::array::from_fn(|i| digit(bytes[2 * i]) * 16 + digit(bytes[2 * i + 1]))
}
pub(super) fn client(profile: Profile) -> (&'static [u8], [u8; 32]) {
    let a = assets(profile);
    (a.client, a.client_sha)
}
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn create(
    a: &mut Authority,
    s: &mut Scheduler,
    r: &mut Registry<'static>,
    custody: SpaceId,
    parent: JobId,
    event_creator: Handle,
    profile: Profile,
    ports: &mut Ports,
    hw: &Hardware,
    frames: &mut BootstrapFrames,
) -> Resources {
    let assets = assets(profile);
    let limits = profile.limits();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(assets.catalogue)),
        assets.catalogue_sha
    );
    let catalogue = Catalogue::decode(assets.catalogue).unwrap();
    // Check coherent build INPUT identity before publishing any readonly page.
    assert_eq!(catalogue.kernel_build, build_identity());
    assert_eq!(catalogue.abi, ev_userspace_contract::ABI);
    assert_eq!(
        catalogue.health,
        <[u8; 32]>::from(Sha256::digest(HEALTH_DESCRIPTION))
    );
    assert_eq!(catalogue.controller, assets.client_sha);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(assets.client)),
        catalogue.controller
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(bundle::M3_BLOCK_DRIVER_IMAGE)),
        catalogue.driver
    );
    for (bytes, expected) in [(assets.a, catalogue.image_a), (assets.b, catalogue.image_b)] {
        assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), expected);
    }
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let job_cap = a
        .create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
        .unwrap();
    let job = s.create_child_job(parent, limits).unwrap();
    r.register_job(a, custody, job_cap, job).unwrap();
    let images = [
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
    ];
    let roles = [
        Role {
            selector: 1,
            kind: Kind::Memory,
            rights: Rights::READ,
        },
        Role {
            selector: 2,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
    ];
    let mut max_frames = 0;
    for (i, (bytes, expected)) in [(assets.a, catalogue.image_a), (assets.b, catalogue.image_b)]
        .into_iter()
        .enumerate()
    {
        let descriptor = ServiceImage::verify(bytes, expected, limits, &roles).unwrap();
        max_frames = max_frames.max(descriptor.plan().unwrap().required_frames());
        r.register_image(a, custody, images[i], descriptor).unwrap();
    }
    let image_objects = images.map(|cap| {
        a.authorize(custody, cap, Kind::Memory, Rights::READ)
            .unwrap()
            .identity()
    });
    let (event_cap, mailbox) = r.create_channel(a, custody, event_creator).unwrap();
    let events = Events::new(mailbox).unwrap_or_else(|_| panic!("new event channel must be empty"));
    let (uart_cap, uart_object) = if profile == Profile::Owner {
        let cap = a
            .create_root(
                custody,
                Kind::IoPorts,
                common | Rights::READ | Rights::WRITE | Rights::CONTROL,
            )
            .unwrap();
        ports
            .register(
                a,
                custody,
                cap,
                &[
                    Range {
                        first: 0x3f8,
                        last: 0x3f8,
                        widths: Widths::BYTE,
                        direction: Direction::Both,
                    },
                    Range {
                        first: 0x3fd,
                        last: 0x3fd,
                        widths: Widths::BYTE,
                        direction: Direction::Input,
                    },
                ],
            )
            .unwrap();
        let object = a
            .authorize(custody, cap, Kind::IoPorts, Rights::CONTROL)
            .unwrap()
            .identity();
        (Some(cap), Some(object))
    } else {
        (None, None)
    };
    s.charge_frames(parent, 1).unwrap();
    let frame = frames.allocate().unwrap();
    let alias = direct_address(hw.offset, frame.start(), hw.bits).unwrap() as *mut u8;
    for i in 0..FRAME_SIZE as usize {
        let byte = assets.catalogue.get(i).copied().unwrap_or(0);
        // SAFETY: sole initialized unpublished RAM owner, full frame bounded.
        unsafe { alias.add(i).write_volatile(byte) };
    }
    for i in 0..FRAME_SIZE as usize {
        // SAFETY: same retained unpublished frame, before any writable alias.
        let byte = unsafe { alias.add(i).read_volatile() };
        assert_eq!(byte, assets.catalogue.get(i).copied().unwrap_or(0));
    }
    let (object, cap) = MemoryObject::new(a, custody, frame).unwrap();
    Resources {
        catalogue,
        digest: assets.catalogue_sha,
        object,
        cap,
        alias,
        job_cap,
        job,
        images,
        image_objects,
        max_frames,
        event_cap,
        events,
        uart_cap,
        uart_object,
    }
}
pub(super) fn expected_stamp(
    catalogue: Catalogue,
    report: &ev_userspace_contract::generation::Completion,
    image: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"evrosion.actual.generation.admission.v1\0");
    hash.update(catalogue.kernel_build);
    for value in [
        report.booted,
        report.boot_serial,
        report.process,
        report.thread,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.update(report.booted_cohort);
    hash.update(image);
    hash.finalize().into()
}
