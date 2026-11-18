extern crate std;
use super::*;
use crate::native_plan;
use ev_store::Sector;
use ev_userspace_contract::{
    block,
    root_v2::{
        self, catalogue as base,
        native::{self, catalogue as nc},
    },
};
use ev_zion::{
    AppId, Capability, CapabilityRequest, Contract, DataSchema, Platform, Version,
    producer::{Resource, Spec},
};
use sha2::{Digest as _, Sha256};
use std::{cell::RefCell, rc::Rc, vec, vec::Vec};
const DEADLINE: u64 = 1500;
const STOP: u64 = 1000;
pub(super) struct Fixture {
    session: bool,
    cat: [u8; nc::SIZE],
    context: ev_userspace_contract::Context,
    a: Vec<u8>,
    b: Vec<u8>,
}
impl Fixture {
    pub(super) fn new() -> Self {
        Self::with_data_declaration(true, true)
    }
    fn with_data_declaration(request: bool, contract: bool) -> Self {
        Self::profile(request, contract, false, false)
    }
    pub(super) fn session_note() -> Self {
        Self::profile(true, true, true, true)
    }
    pub(super) fn session_without_note() -> Self {
        Self::profile(true, true, true, false)
    }
    fn profile(request: bool, contract: bool, session: bool, note: bool) -> Self {
        let elf = include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf");
        let app = AppId::new([4; 16]).unwrap();
        let build = |label| {
            ev_zion::producer::build(
                &Spec {
                    app,
                    name: "Native policy model",
                    source: "Repository test only",
                    publisher: None,
                    version: Version {
                        major: 0,
                        minor: 1,
                        patch: label as u32,
                    },
                    build_id: [label; 32],
                    platform: Platform {
                        minimum: 1,
                        target: 1,
                    },
                    abi: ev_userspace_contract::ABI,
                    data_schema: DataSchema {
                        current: 1,
                        oldest_readable: 1,
                    },
                    entrypoint: "bin/main.elf",
                    contracts: if note {
                        &[
                            Contract {
                                name: "ev.app.private-data",
                                major: 1,
                                minimum_minor: 0,
                                features: 0,
                            },
                            Contract {
                                name: "ev.app.session-note",
                                major: 1,
                                minimum_minor: 0,
                                features: 0,
                            },
                        ]
                    } else if contract {
                        &[Contract {
                            name: "ev.app.private-data",
                            major: 1,
                            minimum_minor: 0,
                            features: 0,
                        }]
                    } else {
                        &[]
                    },
                    capabilities: if request {
                        &[CapabilityRequest {
                            capability: Capability::AppPrivateData,
                            required: true,
                        }]
                    } else {
                        &[]
                    },
                },
                elf,
                &[Resource {
                    path: "res/model.txt",
                    bytes: b"host model only",
                }],
            )
            .unwrap()
        };
        let a = build(5);
        let b = build(6);
        let base = base::encode(base::Description {
            root_image: [1; 32],
            kernel_input: [2; 32],
            graph: [3; 32],
            app_id: app.bytes(),
            package: Sha256::digest(&a).into(),
            app_build: [5; 32],
            provenance: base::Provenance::Zion,
            restart_attempts: 3,
            restart_window: 60000,
            images: core::array::from_fn(|i| base::Image {
                role: root_v2::graph::CHILDREN[i].image(),
                image: if i == 4 {
                    Sha256::digest(elf).into()
                } else {
                    [i as u8 + 10; 32]
                },
                descriptor: [i as u8 + 20; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                display_layout: i == 5,
                grants: base::CHILD_ROLE_COUNTS[i],
                roles: crate::desktop_plan::roles_measurement(root_v2::graph::CHILDREN[i]),
            }),
        })
        .unwrap();
        let desc = |measurement| nc::Description {
            base: &base,
            app_b: nc::AppImage {
                image: Sha256::digest(elf).into(),
                descriptor: [42; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                roles: crate::desktop_plan::roles_measurement(root_v2::graph::Child::App),
            },
            bad_shell: nc::AppImage {
                image: [51; 32],
                descriptor: [52; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                roles: crate::desktop_plan::roles_measurement(root_v2::graph::Child::Shell),
            },
            boot_mode: nc::BootMode::Standalone,
            package_b: Sha256::digest(&b).into(),
            package_b_build: [6; 32],
            package_a_bytes: a.len() as u64,
            package_b_bytes: b.len() as u64,
            layout_measurement: measurement,
        };
        let draft = nc::encode(desc([1; 32])).unwrap();
        let decoded = nc::Catalogue::decode(&draft).unwrap();
        let measurement = if session {
            native_plan::session_layout_measurement(&decoded)
        } else {
            native_plan::layout_measurement(&decoded)
        };
        let cat = nc::encode(desc(measurement)).unwrap();
        let mut context = ev_userspace_contract::Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: crate::desktop_plan::ROOT_LIMITS,
            manifest: [0; 32],
            authority: [4; 32],
        };
        context.manifest = Sha256::digest(
            native::manifest_profile(root_v2::ManifestInputs {
                root_image: [1; 32],
                catalogue: Sha256::digest(cat).into(),
                authority: context.authority,
                limits: context.limits,
                restart_attempts: 3,
                restart_window: 60000,
            })
            .unwrap(),
        )
        .into();
        Self {
            cat,
            context,
            a,
            b,
            session,
        }
    }
    pub(super) fn packages(&self) -> Packages<'_> {
        if self.session {
            Packages::verify_session(&self.cat, self.context, &self.a, &self.b).unwrap()
        } else {
            Packages::verify(&self.cat, self.context, &self.a, &self.b).unwrap()
        }
    }
    fn mode(mut self, mode: nc::BootMode) -> Self {
        self.cat[nc::BOOT_MODE_OFFSET..nc::BOOT_MODE_OFFSET + 2]
            .copy_from_slice(&(mode as u16).to_le_bytes());
        let cat = nc::Catalogue::decode(&self.cat).unwrap();
        let measurement = if self.session {
            native_plan::session_layout_measurement(&cat)
        } else {
            native_plan::layout_measurement(&cat)
        };
        self.cat[1584..1616].copy_from_slice(&measurement);
        self.context.manifest = Sha256::digest(
            native::manifest_profile(root_v2::ManifestInputs {
                root_image: [1; 32],
                catalogue: Sha256::digest(self.cat).into(),
                authority: self.context.authority,
                limits: self.context.limits,
                restart_attempts: 3,
                restart_window: 60000,
            })
            .unwrap(),
        )
        .into();
        self
    }
}
#[derive(Clone)]
pub(crate) struct Buffer(Rc<RefCell<Sector>>);
impl Window for Buffer {
    fn load(&self, out: &mut Sector) {
        *out = *self.0.borrow();
    }
    fn store(&self, input: &Sector) {
        *self.0.borrow_mut() = *input;
    }
}
pub(crate) struct Media {
    pub(super) cache: Vec<Sector>,
    pub(super) durable: Vec<Sector>,
    pub(super) writes: Vec<usize>,
    pub(super) fail_next: bool,
    pub(super) lose_write_reply: bool,
    pub(super) lose_flush_reply: bool,
    calls: Vec<block::Request>,
}
pub(crate) struct Link {
    session: bool,
    network: bool,
    media: Rc<RefCell<Media>>,
    buffer: Buffer,
}
impl Wire for Link {
    type Error = ();
    fn supports_session(&self) -> bool {
        self.network
    }
    fn capture_session_deadline(&self, deadline: u64) -> Option<u64> {
        (self.network && deadline > 100).then_some(deadline.min(1124))
    }
    fn call(&mut self, bytes: [u8; 8], _: u64) -> Result<[u8; 8], ()> {
        let req = block::Request::decode(&bytes).unwrap();
        let mut m = self.media.borrow_mut();
        m.calls.push(req);
        if m.fail_next {
            m.fail_next = false;
            return Err(());
        }
        match req {
            block::Request::Read { sector } => {
                let physical = (if self.network {
                    ev_store::network::physical_sector(sector)
                } else if self.session {
                    ev_store::native::session_physical_sector(sector)
                } else {
                    ev_store::native::physical_sector(sector)
                })
                .unwrap() as usize;
                self.buffer.store(&m.cache[physical]);
            }
            block::Request::Write { sector } => {
                let physical = (if self.network {
                    ev_store::network::physical_sector(sector)
                } else if self.session {
                    ev_store::native::session_physical_sector(sector)
                } else {
                    ev_store::native::physical_sector(sector)
                })
                .unwrap() as usize;
                let mut bytes = [0; 512];
                self.buffer.load(&mut bytes);
                m.cache[physical] = bytes;
                m.writes.push(physical);
                if m.lose_write_reply {
                    m.lose_write_reply = false;
                    return Err(());
                }
            }
            block::Request::Flush => {
                m.durable = m.cache.clone();
                if m.lose_flush_reply {
                    m.lose_flush_reply = false;
                    return Err(());
                }
            }
        }
        Ok(req.success().encode())
    }
}
fn disk() -> Rc<RefCell<Media>> {
    let mut bytes = vec![[0x9b; 512]; 96];
    bytes[64..78].fill([0; 512]);
    bytes[80..94].fill([0; 512]);
    Rc::new(RefCell::new(Media {
        cache: bytes.clone(),
        durable: bytes,
        writes: Vec::new(),
        fail_next: false,
        lose_write_reply: false,
        lose_flush_reply: false,
        calls: Vec::new(),
    }))
}
pub(super) fn composed_disk() -> Rc<RefCell<Media>> {
    let media = disk();
    {
        let mut m = media.borrow_mut();
        m.cache.resize(128, [0x9b; 512]);
        m.cache[16..30].fill([0; 512]);
        m.cache[96..110].fill([0; 512]);
        m.durable = m.cache.clone();
    }
    media
}
fn state(media: Rc<RefCell<Media>>) -> State<Link, Buffer> {
    state_profile(media, false)
}
pub(super) fn state_session(media: Rc<RefCell<Media>>) -> State<Link, Buffer> {
    state_profile(media, true)
}
fn state_profile(media: Rc<RefCell<Media>>, session: bool) -> State<Link, Buffer> {
    state_profile_network(media, session, false)
}
#[cfg(feature = "native-network")]
pub(crate) fn state_network(media: Rc<RefCell<Media>>) -> State<Link, Buffer> {
    state_profile_network(media, true, true)
}
fn state_profile_network(
    media: Rc<RefCell<Media>>,
    session: bool,
    network: bool,
) -> State<Link, Buffer> {
    let buffer = Buffer(Rc::new(RefCell::new([0; 512])));
    let backend = Backend::new(
        Link {
            media,
            session,
            network,
            buffer: buffer.clone(),
        },
        buffer,
        if network { 0 } else { STOP },
    )
    .unwrap();
    #[cfg(feature = "native-network")]
    if network {
        return State::new_downloaded_v2(backend);
    }
    State::new(backend)
}
pub(crate) fn cold(media: &Rc<RefCell<Media>>) {
    let mut m = media.borrow_mut();
    m.cache = m.durable.clone();
}
pub(super) fn transition(s: &mut State<Link, Buffer>, p: &Packages<'_>, change: Change) {
    s.fence();
    s.prepare(p, change, DEADLINE).unwrap();
    s.commit(p, DEADLINE).unwrap();
}
const WHO: Identity = Identity {
    process: 7,
    thread: 8,
};
#[test]
fn actual_package_bytes_are_reparsed_and_wrong_bank_identity_or_length_refuses() {
    let f = Fixture::new();
    let p = f.packages();
    assert_ne!(p.digest(Slot::A), p.digest(Slot::B));
    assert!(Packages::verify(&f.cat, f.context, &f.b, &f.a).is_err());
    assert!(Packages::verify(&f.cat, f.context, &f.a[..f.a.len() - 1], &f.b).is_err());
    let mut b = f.b.clone();
    *b.last_mut().unwrap() ^= 1;
    assert!(Packages::verify(&f.cat, f.context, &f.a, &b).is_err());
}
#[test]
fn coherent_recipe_preserves_mode_independence_but_admission_binds_actual_boot() {
    use native_plan::system;
    let normal = Fixture::new().mode(nc::BootMode::SystemManaged);
    let recovery = Fixture::new().mode(nc::BootMode::Recovery);
    let a = normal.packages();
    let b = recovery.packages();
    assert_ne!(normal.context.manifest, recovery.context.manifest);
    assert_eq!(system::catalogue_recipe(&a), system::catalogue_recipe(&b));
    let good = system::manifest(&a, system::Slot::Good, 1).unwrap();
    assert_eq!(good, system::manifest(&b, system::Slot::Good, 1).unwrap());
    let bad = system::manifest(&a, system::Slot::Bad, 2).unwrap();
    assert_eq!(good.supervisor_image, bad.supervisor_image);
    assert_ne!(good.cohort, bad.cohort);
    assert_eq!(system::resolve(&a, &bad), Ok(system::Slot::Bad));
    let mut alien = bad;
    alien.cohort[1] ^= 1;
    assert_eq!(system::resolve(&a, &alien), Err(system::Error::Manifest));
    let plan = ev_store::BootPlan {
        manifest: good,
        serial: 1,
        candidate: true,
        attempt: 1,
    };
    let before = system::admission(&a, normal.context, 3, 4, plan).unwrap();
    let after = system::admission(&b, recovery.context, 3, 4, plan).unwrap();
    assert_ne!(before.process_stamp, after.process_stamp);
    assert!(system::admission(&a, normal.context, 9, 4, plan).is_err());
}
fn begin_system(
    s: &mut State<Link, Buffer>,
    p: &Packages<'_>,
    f: &Fixture,
) -> ev_store::AdmissionReport {
    let selected = s
        .system_snapshot(DEADLINE)
        .unwrap()
        .unwrap()
        .selected
        .unwrap();
    let view = s
        .system_apply(SystemChange::BeginBoot(selected.generation), DEADLINE)
        .unwrap();
    let admitted =
        native_plan::system::admission(p, f.context, f.context.process, 4, view.boot_plan.unwrap())
            .unwrap();
    s.system_apply(SystemChange::Admission(admitted), DEADLINE)
        .unwrap();
    admitted
}
fn healthy_system(s: &mut State<Link, Buffer>, admitted: ev_store::AdmissionReport) -> SystemView {
    let probe = native_plan::system::probe(admitted);
    s.system_apply(SystemChange::Probe(probe), DEADLINE)
        .unwrap();
    s.system_apply(
        SystemChange::Health(ev_store::HealthReport {
            admitted,
            outcome: ev_store::HealthOutcome::CriticalPassed,
            observed_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
            storage_probe: Sha256::digest(probe).into(),
        }),
        DEADLINE,
    )
    .unwrap()
}
#[test]
fn five_cold_system_phases_keep_current_admission_distinct_and_preserve_live_app_data() {
    use native_plan::system;
    let f = Fixture::new().mode(nc::BootMode::SystemManaged);
    let p = f.packages();
    let media = composed_disk();
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    s.install(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    let preserved = media.borrow().durable[32..].to_vec();
    assert!(s.system_snapshot(DEADLINE).unwrap().is_none());
    let initial = s.system_initialize(&p, DEADLINE).unwrap();
    assert_eq!(initial.next_operation.get(), 1);
    assert_eq!(initial.known_good, None);
    let good = begin_system(&mut s, &p, &f);
    let view = healthy_system(&mut s, good);
    assert_eq!(view.known_good, Some(1));
    assert_eq!(view.next_operation.get(), 5);
    let good_probe = s.system_probe_digest(DEADLINE).unwrap();
    let bad = system::manifest(&p, system::Slot::Bad, 2).unwrap();
    s.system_apply(SystemChange::Stage(bad), DEADLINE).unwrap();
    let staged = s.system_readonly_snapshot(DEADLINE).unwrap().unwrap();
    assert_eq!(staged.staged, Some(bad));
    assert_eq!(staged.selected.unwrap().generation.get(), 1);
    let view = s
        .system_apply(SystemChange::Activate(bad.generation), DEADLINE)
        .unwrap();
    assert_eq!(view.selected, Some(bad));
    assert_eq!(good.generation.get(), 1);
    assert_eq!(view.next_operation.get(), 7);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let failed = begin_system(&mut s, &p, &f);
    assert_eq!(failed.generation.get(), 2);
    assert_ne!(failed.process_stamp, good.process_stamp);
    let view = s
        .system_apply(
            SystemChange::Health(ev_store::HealthReport {
                admitted: failed,
                outcome: ev_store::HealthOutcome::MissingProgress,
                observed_checks: 0,
                storage_probe: good_probe,
            }),
            DEADLINE,
        )
        .unwrap();
    assert_eq!(view.selected.unwrap().generation.get(), 1);
    assert_eq!(failed.generation.get(), 2);
    assert_eq!(view.known_good, Some(1));
    assert_eq!(view.boot_serial, 2);
    assert_eq!(view.next_operation.get(), 10);
    assert_eq!(
        view.last_failure.unwrap().reason,
        ev_store::LastFailureReason::MissingProgress
    );
    assert_eq!(s.system_probe_digest(DEADLINE).unwrap(), good_probe);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let returned = begin_system(&mut s, &p, &f);
    let view = healthy_system(&mut s, returned);
    assert_eq!(view.next_operation.get(), 14);
    assert_eq!(view.boot_serial, 3);
    let bad = system::manifest(&p, system::Slot::Bad, 3).unwrap();
    s.system_apply(SystemChange::Stage(bad), DEADLINE).unwrap();
    let view = s
        .system_apply(SystemChange::Activate(bad.generation), DEADLINE)
        .unwrap();
    assert_eq!(view.next_operation.get(), 16);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let before = media.borrow().writes.len();
    let head = s.system_readonly_snapshot(DEADLINE).unwrap().unwrap();
    assert_eq!(media.borrow().writes.len(), before);
    assert_eq!(head.selected, Some(bad));
    let selected = s
        .system_apply(SystemChange::SelectKnownGood, DEADLINE)
        .unwrap();
    assert_eq!(selected.selected.unwrap().generation.get(), 1);
    assert_eq!(selected.boot_serial, 3);
    assert_eq!(selected.next_operation.get(), 17);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let final_good = begin_system(&mut s, &p, &f);
    let view = healthy_system(&mut s, final_good);
    assert_eq!(view.next_operation.get(), 21);
    assert_eq!(view.boot_serial, 4);
    assert_eq!(view.known_good, Some(1));
    s.open(&p, DEADLINE).unwrap();
    assert_eq!(s.active(&p), Ok(Some(Slot::A)));
    s.admit(&p, Slot::A, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    assert_eq!(&media.borrow().durable[32..], &preserved);
    assert!(
        media
            .borrow()
            .writes
            .iter()
            .all(|i| (16..30).contains(i) || (64..78).contains(i) || (80..94).contains(i))
    );
}
#[test]
fn system_unknown_completion_fences_same_boot_and_readonly_cold_open_never_replays() {
    let f = Fixture::new();
    let p = f.packages();
    let media = composed_disk();
    let mut s = state(media.clone());
    s.system_initialize(&p, DEADLINE).unwrap();
    let admitted = begin_system(&mut s, &p, &f);
    healthy_system(&mut s, admitted);
    media.borrow_mut().lose_flush_reply = true;
    assert!(
        s.system_apply(
            SystemChange::Stage(
                native_plan::system::manifest(&p, native_plan::system::Slot::Bad, 2).unwrap()
            ),
            DEADLINE
        )
        .is_err()
    );
    assert!(s.recovery_required());
    assert!(s.system_pending.is_some());
    let count = media.borrow().writes.len();
    assert_eq!(
        s.system_apply(SystemChange::SelectKnownGood, DEADLINE)
            .err(),
        Some(Error::Recovery)
    );
    assert_eq!(media.borrow().writes.len(), count);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let count = media.borrow().writes.len();
    assert!(s.system_readonly_snapshot(DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), count);
    let recovered = s.system_snapshot(DEADLINE).unwrap().unwrap();
    assert_eq!(recovered.staged.unwrap().generation.get(), 2);
    assert_eq!(recovered.next_operation.get(), 6);
    let count = media.borrow().writes.len();
    let mut s = state(media.clone());
    assert!(s.system_initialize(&p, DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), count);
}
fn grant_user() -> ev_picker::UserId {
    ev_picker::UserId::new(*b"EVROSION-OWNER01").unwrap()
}
fn grant_requester(p: &Packages<'_>, revision: u64, process: u64) -> ev_picker::Requester {
    ev_picker::Requester {
        user: grant_user(),
        session: ev_picker::SessionId::new([2; 16]).unwrap(),
        app: ev_picker::AppRef {
            app: p.app(),
            package: ev_picker::ContentDigest::new(p.digest(Slot::A)).unwrap(),
        },
        incarnation: ev_picker::Incarnation::new(
            ev_picker::BootEpoch::new([3; 16]).unwrap(),
            process,
        )
        .unwrap(),
        policy_revision: revision,
        alive: true,
    }
}
fn grant_object() -> ev_picker::ObjectView {
    ev_picker::ObjectView {
        object: ev_picker::ObjectId::new(
            ev_picker::VolumeId::new(*b"EVRO-USERS-VOL01").unwrap(),
            1,
        )
        .unwrap(),
        revision: ev_picker::Revision::new(0, ev_picker::ContentDigest::new([8; 32]).unwrap())
            .unwrap(),
        permission_revision: 1,
        readable: true,
    }
}
// This fixture callback exercises the real Picker validation and actual sole
// State backend publication. Its unit return models no physical capability.
struct PublishGrant<'s, 'p, 'a> {
    state: &'s mut State<Link, Buffer>,
    packages: &'p Packages<'a>,
    expected: ev_grant_policy::Expected,
    observed: bool,
}
impl ev_picker::Handoff for PublishGrant<'_, '_, '_> {
    type Delivered = ();
    type Error = Error;
    fn revalidate_and_deliver_read(
        &mut self,
        delivery: ev_picker::ReadDelivery<'_>,
    ) -> ev_picker::Delivery<(), Error> {
        match self.state.grant_remember(
            self.packages,
            grant_user(),
            self.expected,
            &delivery,
            DEADLINE,
        ) {
            Ok(_) => {
                let actual = self
                    .state
                    .grant_snapshot(self.packages, grant_user(), DEADLINE)
                    .unwrap();
                assert_eq!(actual.expected.unwrap().revision, 1);
                assert!(actual.record.is_some_and(|r| !r.revoked()));
                self.observed = true;
                ev_picker::Delivery::Delivered(())
            }
            Err(e) => ev_picker::Delivery::Refused(e),
        }
    }
}
fn remember_grant(s: &mut State<Link, Buffer>, p: &Packages<'_>) -> bool {
    let snapshot = s.grant_snapshot(p, grant_user(), DEADLINE).unwrap();
    let current = grant_requester(p, snapshot.requester_revision(), 7);
    let object = grant_object();
    let mut picker =
        ev_picker::Picker::new(ev_picker::PickerEpoch::new([9; 16]).unwrap(), 32).unwrap();
    let a = picker
        .prepare(
            current,
            object,
            ev_picker::Persistence::RememberPerUser,
            10,
            30,
        )
        .unwrap();
    let consent = ev_picker::Consent {
        displayed_action: a.selection().action_digest(),
        approver: grant_user(),
        origin: ev_picker::Origin::ExplicitOwnerAction,
    };
    let mut writer = PublishGrant {
        state: s,
        packages: p,
        expected: snapshot.expected.unwrap(),
        observed: false,
    };
    let result = picker
        .commit(a, consent, current, object, 11, &mut writer)
        .unwrap();
    assert_eq!(
        matches!(result, ev_picker::Delivery::Delivered(())),
        writer.observed
    );
    writer.observed
}
#[derive(Default)]
struct RemintProbe {
    calls: usize,
}
impl ev_grant_policy::FreshReadHandoff for RemintProbe {
    type Ticket = ();
    type Error = ();
    fn enqueue_fresh_read(
        &mut self,
        eligible: ev_grant_policy::Eligible<'_>,
    ) -> ev_picker::Delivery<(), ()> {
        assert_eq!(eligible.record().head(), eligible.head());
        self.calls += 1;
        ev_picker::Delivery::Delivered(())
    }
}
#[test]
fn sole_backend_policy_publish_precedes_handoff_and_cold_tombstone_never_remints() {
    let f = Fixture::new();
    let p = f.packages();
    let media = composed_disk();
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    s.install(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    let outside = media.borrow().durable.clone();
    assert!(
        s.grant_snapshot(&p, grant_user(), DEADLINE)
            .unwrap()
            .expected
            .is_none()
    );
    assert_eq!(s.grant_initialize(&p, grant_user(), DEADLINE), Ok(()));
    assert_eq!(
        s.grant_snapshot(&p, grant_user(), DEADLINE)
            .unwrap()
            .expected
            .unwrap()
            .revision,
        0
    );
    assert!(remember_grant(&mut s, &p));
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    s.admit(&p, Slot::A, WHO).unwrap();
    let head = s.grant_snapshot(&p, grant_user(), DEADLINE).unwrap();
    let mut current = grant_requester(&p, head.requester_revision(), 90);
    current.session = ev_picker::SessionId::new([0x33; 16]).unwrap();
    let mut probe = RemintProbe::default();
    assert!(matches!(
        s.grant_remint(
            &p,
            grant_user(),
            current,
            grant_object(),
            DEADLINE,
            &mut probe
        ),
        Ok(ev_picker::Delivery::Delivered(()))
    ));
    assert_eq!(probe.calls, 1);
    // Exact package identity is enforced against the actual current incarnation.
    current.app.package = ev_picker::ContentDigest::new(p.digest(Slot::B)).unwrap();
    assert!(
        s.grant_remint(
            &p,
            grant_user(),
            current,
            grant_object(),
            DEADLINE,
            &mut probe
        )
        .is_err()
    );
    assert_eq!(probe.calls, 1);
    s.grant_prepare_revoke(&p, grant_user(), head.expected.unwrap(), DEADLINE)
        .unwrap();
    assert!(s.grants_fenced());
    assert!(s.grant_pending.is_some());
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    assert!(
        s.grant_remint(
            &p,
            grant_user(),
            grant_requester(&p, 1, 90),
            grant_object(),
            DEADLINE,
            &mut probe
        )
        .is_err()
    );
    assert_eq!(probe.calls, 1);
    let published = s.grant_commit_revoke(&p, grant_user(), DEADLINE).unwrap();
    assert_eq!(published.operation.get(), 2);
    assert_eq!(published.revision, 2);
    assert!(!s.grants_fenced());
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let tombstone = s.grant_snapshot(&p, grant_user(), DEADLINE).unwrap();
    assert!(tombstone.record.unwrap().revoked());
    assert_eq!(tombstone.expected.unwrap().revision, 2);
    assert!(
        s.grant_remint(
            &p,
            grant_user(),
            grant_requester(&p, 2, 99),
            grant_object(),
            DEADLINE,
            &mut probe
        )
        .is_err()
    );
    assert_eq!(probe.calls, 1);
    let actual = &media.borrow().durable;
    for i in 0..128 {
        if !(96..110).contains(&i) {
            assert_eq!(actual[i], outside[i]);
        }
    }
}
#[test]
fn uncertain_policy_publication_retains_exact_intent_and_partial_namespaces_never_format() {
    let f = Fixture::new();
    let p = f.packages();
    let media = composed_disk();
    let mut s = state(media.clone());
    s.grant_initialize(&p, grant_user(), DEADLINE).unwrap();
    media.borrow_mut().lose_flush_reply = true;
    assert!(!remember_grant(&mut s, &p));
    assert!(s.recovery_required());
    assert!(s.grants_fenced());
    assert!(s.grant_pending.is_some());
    let pending = s.grant_pending.as_ref().unwrap().operation();
    assert_eq!(pending.get(), 1);
    let writes = media.borrow().writes.len();
    assert!(s.grant_initialize(&p, grant_user(), DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), writes);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    let recovered = s.grant_snapshot(&p, grant_user(), DEADLINE).unwrap();
    assert_eq!(recovered.expected.unwrap().revision, 1);
    assert!(recovered.record.is_some_and(|r| !r.revoked()));
    let media = composed_disk();
    media.borrow_mut().cache[109][511] = 1;
    let mut s = state(media.clone());
    let writes = media.borrow().writes.len();
    assert!(s.grant_initialize(&p, grant_user(), DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), writes);
    assert!(s.recovery_required());
    let media = composed_disk();
    media.borrow_mut().cache[29][511] = 1;
    let mut s = state(media.clone());
    let writes = media.borrow().writes.len();
    assert!(s.system_initialize(&p, DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), writes);
    assert!(s.recovery_required());
}
#[test]
fn cached_native_views_pin_exact_bank_bytes_and_keep_current_requirement_checks() {
    use ev_app_registry::Packages as _;
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let a = packages.checked(Slot::A).unwrap();
    let b = packages.checked(Slot::B).unwrap();
    assert!(core::ptr::eq(a, packages.checked(Slot::A).unwrap()));
    assert!(!core::ptr::eq(a, b));
    assert_eq!(a.bytes().as_ptr(), fixture.a.as_ptr());
    assert_eq!(a.bytes().len(), fixture.a.len());
    assert_eq!(b.bytes().as_ptr(), fixture.b.as_ptr());
    assert_eq!(b.bytes().len(), fixture.b.len());
    assert!(core::ptr::eq(
        a,
        packages.parsed(packages.digest(Slot::A)).unwrap()
    ));
    assert!(core::ptr::eq(
        b,
        packages.parsed(packages.digest(Slot::B)).unwrap()
    ));
    assert!(packages.parsed([0x99; 32]).is_none());
    assert!(matches!(
        a.compatible(0, ev_userspace_contract::ABI, &Contracts),
        Err(ev_zion::Error::Platform)
    ));
    assert!(matches!(
        a.compatible(1, [0; 32], &Contracts),
        Err(ev_zion::Error::Abi)
    ));
    struct Unsupported;
    impl ev_zion::Contracts for Unsupported {
        fn supported(&self, _: &str, _: u16) -> Option<ev_zion::ContractSupport> {
            None
        }
    }
    assert!(matches!(
        a.compatible(1, ev_userspace_contract::ABI, &Unsupported),
        Err(ev_zion::Error::UnsupportedContract)
    ));
}
#[test]
fn matching_container_digest_cannot_substitute_for_declared_private_data_authority() {
    for (request, contract) in [(false, false), (false, true), (true, false)] {
        let fixture = Fixture::with_data_declaration(request, contract);
        assert!(matches!(
            Packages::verify(&fixture.cat, fixture.context, &fixture.a, &fixture.b),
            Err(native_plan::PackageError::PrivateData)
        ));
    }
}
#[test]
fn six_cold_lifecycle_phases_preserve_data_and_never_write_other_regions() {
    let f = Fixture::new();
    let p = f.packages();
    let media = disk();
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    assert_eq!(s.mutations(), 0);
    assert_eq!(s.active(&p), Ok(None));
    s.install(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    s.metadata(
        &p,
        Change::Stage {
            package: p.digest(Slot::B),
        },
        DEADLINE,
    )
    .unwrap();
    assert_eq!(s.active(&p), Ok(Some(Slot::A)));
    assert_eq!(s.record().unwrap().revision(), 3);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::B, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Value(2026)
    );
    assert_eq!(s.data().unwrap().counter(), 1);
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    assert_eq!(s.data().unwrap().value(), 2026);
    transition(&mut s, &p, Change::Rollback);
    s.admit(&p, Slot::A, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(2026)
    );
    transition(&mut s, &p, Change::Remove);
    assert!(!s.record().unwrap().installed());
    assert_eq!(s.active(&p), Ok(None));
    drop(s);
    cold(&media);
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    assert_eq!(s.data().unwrap().value(), 2026);
    s.metadata(
        &p,
        Change::Reinstall {
            package: p.digest(Slot::A),
        },
        DEADLINE,
    )
    .unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(2026)
    );
    assert_eq!(s.record().unwrap().data_epoch(), 1);
    assert_eq!(s.data().unwrap().counter(), 1);
    let m = media.borrow();
    assert!(
        m.writes
            .iter()
            .all(|n| (64..78).contains(n) || (80..94).contains(n))
    );
    for i in 0..96 {
        if !(64..78).contains(&i) && !(80..94).contains(&i) {
            assert_eq!(m.durable[i], [0x9b; 512]);
        }
    }
}
#[test]
fn old_sender_duplicate_set_and_fenced_incarnation_cannot_mutate_data() {
    let f = Fixture::new();
    let p = f.packages();
    let media = disk();
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    s.install(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    let before = s.mutations();
    let wrong = Identity {
        process: WHO.process,
        thread: WHO.thread + 1,
    };
    assert_eq!(
        s.data_request(&p, wrong, DataRequest::SetValue(2026), DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    assert_eq!(s.mutations(), before);
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    // A successful actual Store write is allowed only once per incarnation.
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Value(2026)
    );
    let after_write = s.mutations();
    assert!(after_write > before);
    let saved = s.data().unwrap();
    assert_eq!((saved.counter(), saved.value()), (1, 2026));
    for request in [
        DataRequest::Read,
        DataRequest::SetValue(2027),
        DataRequest::SetValue(2026),
    ] {
        assert_eq!(
            s.data_request(&p, WHO, request, DEADLINE),
            Response::Refused(Refusal::Denied)
        );
    }
    s.fence();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::SetValue(2027), DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    assert_eq!(s.mutations(), after_write);
    // Same active package in a new actual incarnation sees the old durable
    // value. An old Process ID or Thread ID cannot borrow that new session.
    let replacement = Identity {
        process: WHO.process + 256,
        thread: WHO.thread + 256,
    };
    s.admit(&p, Slot::A, replacement).unwrap();
    for old in [
        WHO,
        Identity {
            process: replacement.process,
            thread: WHO.thread,
        },
        Identity {
            process: WHO.process,
            thread: replacement.thread,
        },
    ] {
        assert_eq!(
            s.data_request(&p, old, DataRequest::Read, DEADLINE),
            Response::Refused(Refusal::Denied)
        );
    }
    assert_eq!(
        s.data_request(&p, replacement, DataRequest::Read, DEADLINE),
        Response::Value(2026)
    );
    assert_eq!(s.mutations(), after_write);
    drop(s);
    cold(&media);
    let mut reopened = state(media);
    reopened.open(&p, DEADLINE).unwrap();
    assert_eq!(reopened.data(), Some(saved));
}
#[test]
fn partial_or_corrupt_allocation_and_ambiguous_write_never_format_or_retry() {
    let f = Fixture::new();
    let p = f.packages();
    let media = disk();
    media.borrow_mut().cache[80][0] = 1;
    let mut s = state(media.clone());
    assert!(s.open(&p, DEADLINE).is_err());
    assert!(s.install(&p, DEADLINE).is_err());
    assert!(media.borrow().writes.is_empty());
    let media = disk();
    let mut s = state(media.clone());
    s.open(&p, DEADLINE).unwrap();
    s.install(&p, DEADLINE).unwrap();
    transition(&mut s, &p, Change::Activate);
    s.admit(&p, Slot::A, WHO).unwrap();
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    media.borrow_mut().fail_next = true;
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Refused(Refusal::Storage)
    );
    let writes = media.borrow().writes.len();
    assert!(s.recovery_required());
    assert_eq!(
        s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Refused(Refusal::Storage)
    );
    assert_eq!(writes, media.borrow().writes.len());
}

#[test]
fn accepted_device_mutation_with_lost_reply_is_fenced_and_cold_replays_at_most_once() {
    let f = Fixture::new();
    let p = f.packages();
    for durable_intent in [false, true] {
        let media = disk();
        let mut s = state(media.clone());
        s.open(&p, DEADLINE).unwrap();
        s.install(&p, DEADLINE).unwrap();
        transition(&mut s, &p, Change::Activate);
        s.admit(&p, Slot::A, WHO).unwrap();
        assert_eq!(
            s.data_request(&p, WHO, DataRequest::Read, DEADLINE),
            Response::Value(1001)
        );
        if durable_intent {
            media.borrow_mut().lose_flush_reply = true;
        } else {
            media.borrow_mut().lose_write_reply = true;
        }
        let old_writes = media.borrow().writes.len();
        assert_eq!(
            s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
            Response::Refused(Refusal::Storage)
        );
        assert!(s.recovery_required());
        let writes = media.borrow().writes.len();
        assert!(
            writes > old_writes,
            "test must lose reply AFTER an accepted physical mutation"
        );
        assert_eq!(
            s.data_request(&p, WHO, DataRequest::SetValue(2026), DEADLINE),
            Response::Refused(Refusal::Storage)
        );
        assert_eq!(
            media.borrow().writes.len(),
            writes,
            "uncertain request must not be retried"
        );
        drop(s);
        cold(&media);
        let mut reopened = state(media.clone());
        reopened.open(&p, DEADLINE).unwrap();
        let actual = reopened.data().unwrap();
        assert_eq!(
            (actual.counter(), actual.value()),
            if durable_intent { (1, 2026) } else { (0, 1001) }
        );
        drop(reopened);
        cold(&media);
        let writes = media.borrow().writes.len();
        let mut twice = state(media.clone());
        twice.open(&p, DEADLINE).unwrap();
        assert_eq!(twice.data(), Some(actual));
        assert_eq!(
            media.borrow().writes.len(),
            writes,
            "already recovered operation must not apply twice"
        );
    }
}

#[path = "install_tests.rs"]
mod install_tests;

#[path = "launch_tests.rs"]
mod launch_tests;

#[cfg(feature = "native-network")]
#[path = "../native_sources/state_tests.rs"]
pub(crate) mod downloaded_sources;

#[cfg(feature = "native-network")]
#[path = "state_tests/settled_update.rs"]
mod settled_update;

#[cfg(feature = "native-network")]
pub(crate) fn health_bytes(media: &Rc<RefCell<Media>>) -> Vec<Sector> {
    media.borrow().durable.clone()
}

/// Count real transport requests, including reads and failed calls.
#[cfg(feature = "native-network")]
pub(crate) fn storage_calls(media: &Rc<RefCell<Media>>) -> usize {
    media.borrow().calls.len()
}

#[cfg(feature = "native-network")]
#[test]
fn fixed_system_profile_uses_explicit_constructor_not_feature_or_mutable_media() {
    let f = Fixture::new();
    let p = f.packages();
    let legacy = native_plan::system::manifest(&p, native_plan::system::Slot::Good, 1).unwrap();
    let media = composed_disk();
    let mut downloaded = state_network(media.clone());
    let mut manifest = legacy;
    manifest.health_version = 2;
    manifest.health_contract = Sha256::digest(crate::downloaded_health::HEALTH_DESCRIPTION).into();
    // Fixture metadata, not a claim that an unverified subject was admitted.
    downloaded
        .initialize_downloaded_manifest(manifest, DEADLINE)
        .unwrap();
    assert_eq!(
        downloaded
            .system_snapshot(DEADLINE)
            .unwrap()
            .unwrap()
            .selected,
        Some(manifest)
    );
    assert!(
        matches!(downloaded.inspect_system(DEADLINE),crate::native_diagnostics::system::State::Committed {selected,..} if selected==manifest)
    );
    let backend = downloaded.take_content_backend(false).unwrap();
    downloaded
        .restore_content_backend(backend)
        .unwrap_or_else(|_| panic!("same backend"));
    assert_eq!(
        downloaded
            .system_snapshot(DEADLINE)
            .unwrap()
            .unwrap()
            .selected,
        Some(manifest)
    );
    drop(downloaded);
    cold(&media);
    let before = health_bytes(&media);
    let writes = media.borrow().writes.len();
    let mut ordinary = state(media.clone());
    assert!(ordinary.system_snapshot(DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), writes);
    assert_eq!(health_bytes(&media), before);
    assert!(matches!(
        ordinary.inspect_system(DEADLINE),
        crate::native_diagnostics::system::State::Unavailable
    ));
    drop(ordinary);
    let media = composed_disk();
    let mut ordinary = state(media.clone());
    ordinary.system_initialize(&p, DEADLINE).unwrap();
    assert_eq!(
        ordinary
            .system_snapshot(DEADLINE)
            .unwrap()
            .unwrap()
            .selected,
        Some(legacy)
    );
    drop(ordinary);
    cold(&media);
    let before = health_bytes(&media);
    let writes = media.borrow().writes.len();
    let mut downloaded = state_network(media.clone());
    assert!(downloaded.system_snapshot(DEADLINE).is_err());
    assert_eq!(media.borrow().writes.len(), writes);
    assert_eq!(health_bytes(&media), before);
}
