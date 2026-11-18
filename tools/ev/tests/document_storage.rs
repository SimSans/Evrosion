//! Cross-layer M7 failure evidence at MODEL scope. These tests run the real
//! Editor, File codec, endpoint-bound DesktopGateway and Store-v2 implementation.
//! The backend models volatile cache, durable media, torn sectors and power loss.
//! It is not an IPC, kernel-grant, physical-device or actual-VM interruption proof.
use ev_file::{
    Envelope, Error as FileError, Payload, Request, Response,
    desktop::{DesktopBindings, DesktopGateway, Object, SEED_PRIVATE},
};
use ev_native_hello::document::{Editor, Error as EditorError, Navigation, Proposal};
use ev_store::{
    BootPolicy, Error as StoreError, GenerationId, GenerationManifest, ObjectId, Sector, SectorIo,
    Store, desktop::Region,
};
use ev_userspace_contract::{
    document::{Access, Choice, Feedback, State},
    file::{DecodeError, ErrorCode},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc};

const DEADLINE: u64 = 100_000;
const NOTES_RO: u64 = 10;
const NOTES_RW: u64 = 11;
const PRIVATE_RO: u64 = 12;
const PRIVATE_RW: u64 = 13;
const SECTORS: usize = 8192;
const OLD: &[u8] = b"Owner's existing document.";
const NEW: &str = " Later owner edit: é界.";
type Image = Vec<Sector>;
type Gateway = DesktopGateway<RegionIo>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Power,
    Offline,
    Bounds,
    ReadOnly,
}
#[derive(Clone, Copy, Debug)]
enum Cut {
    Before,
    After,
    Torn,
}
const CUTS: [Cut; 3] = [Cut::Before, Cut::After, Cut::Torn];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Io {
    Read,
    Write,
    Flush,
}

struct Media {
    durable: Image,
    cache: Image,
    armed: Option<(usize, Cut)>,
    notes_trace: Vec<Io>,
    all_io: usize,
    writes: Vec<usize>,
    flushes: usize,
    offline: bool,
}
struct Control(Rc<RefCell<Media>>);
// A region device cannot be cloned. The only constructor below returns exactly
// one device for each disjoint File region; the controller has no SectorIo impl.
struct RegionIo {
    media: Rc<RefCell<Media>>,
    region: Region,
    sectors: u64,
}
fn devices(image: Image, notes_sectors: u64) -> (Control, RegionIo, RegionIo) {
    assert_eq!(image.len(), SECTORS);
    let media = Rc::new(RefCell::new(Media {
        cache: image.clone(),
        durable: image,
        armed: None,
        notes_trace: Vec::new(),
        all_io: 0,
        writes: Vec::new(),
        flushes: 0,
        offline: false,
    }));
    let notes = RegionIo {
        media: media.clone(),
        region: Region::FileA,
        sectors: notes_sectors,
    };
    let private = RegionIo {
        media: media.clone(),
        region: Region::FileB,
        sectors: 14,
    };
    (Control(media), notes, private)
}
impl Control {
    fn arm_in(&self, step: usize, cut: Cut) {
        let mut media = self.0.borrow_mut();
        assert!(step > 0 && !media.offline && media.armed.is_none());
        media.armed = Some((media.notes_trace.len() + step, cut));
    }
    fn trace(&self) -> Vec<Io> {
        self.0.borrow().notes_trace.clone()
    }
    fn counts(&self) -> (usize, usize, usize) {
        let media = self.0.borrow();
        (media.all_io, media.writes.len(), media.flushes)
    }
    fn cold(self) -> Image {
        // Consuming/dropping BOTH Store owners is required before cold recovery.
        // There is no model recovery alongside a surviving writer/backend alias.
        assert_eq!(Rc::strong_count(&self.0), 1, "old writers must be stopped");
        Rc::try_unwrap(self.0).ok().unwrap().into_inner().durable
    }
}
impl RegionIo {
    fn begin(&self, io: Io, lba: u64) -> Result<Option<Cut>, Fault> {
        if lba >= self.sectors {
            return Err(Fault::Bounds);
        }
        let mut media = self.media.borrow_mut();
        if media.offline {
            return Err(Fault::Offline);
        }
        media.all_io += 1;
        if self.region != Region::FileA {
            return Ok(None);
        }
        media.notes_trace.push(io);
        Ok(media
            .armed
            .filter(|(at, _)| *at == media.notes_trace.len())
            .map(|(_, cut)| cut))
    }
    fn lost(&self) -> Result<(), Fault> {
        self.media.borrow_mut().offline = true;
        Err(Fault::Power)
    }
    fn physical(&self, local: u64) -> usize {
        self.region.physical_start() as usize + local as usize
    }
}
impl SectorIo for RegionIo {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), Fault> {
        let cut = self.begin(Io::Read, lba)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        *out = self.media.borrow().cache[self.physical(lba)];
        if cut.is_some() {
            return self.lost();
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, input: &Sector, _: u64) -> Result<(), Fault> {
        let cut = self.begin(Io::Write, lba)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        let physical = self.physical(lba);
        {
            let mut media = self.media.borrow_mut();
            media.writes.push(physical);
            media.cache[physical] = *input;
            match cut {
                Some(Cut::After) => media.durable[physical] = *input,
                Some(Cut::Torn) => media.durable[physical][..257].copy_from_slice(&input[..257]),
                _ => (),
            }
        }
        if cut.is_some() {
            return self.lost();
        }
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), Fault> {
        let cut = self.begin(Io::Flush, 0)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        {
            let mut media = self.media.borrow_mut();
            media.flushes += 1;
            if matches!(cut, Some(Cut::Torn)) {
                // Only a subset of dirty sectors reaches stable media.
                for local in (0..14).step_by(2) {
                    let physical = self.physical(local);
                    media.durable[physical] = media.cache[physical];
                }
            } else {
                media.durable = media.cache.clone();
            }
        }
        if cut.is_some() {
            return self.lost();
        }
        Ok(())
    }
}
fn bindings() -> DesktopBindings {
    DesktopBindings::new(NOTES_RO, NOTES_RW, PRIVATE_RO, PRIVATE_RW).unwrap()
}
fn container(object: Object) -> GenerationManifest {
    // Same unresolved data-container schema as services/file/desktop_actor.rs.
    // No fabricated admitted process, successful health or Known Good state.
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [object.stable_id() as u8; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn format(device: RegionIo, object: Object, payload: &[u8]) -> Store<RegionIo> {
    let mut bytes = [0; 256];
    let n = Envelope::initial(payload).unwrap().encode(&mut bytes);
    Store::format_new(
        device,
        container(object),
        &bytes[..n],
        BootPolicy::new(3).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|r| panic!("model provisioning: {:?}", r.error))
}
struct Mounted {
    gateway: Gateway,
    control: Control,
}
struct Rejected {
    error: StoreError<Fault>,
    control: Control,
}
impl Mounted {
    fn open(image: Image) -> Self {
        Self::try_open(image, 14, None).unwrap_or_else(|r| panic!("model reopen: {:?}", r.error))
    }
    fn try_open(
        image: Image,
        notes_sectors: u64,
        cut: Option<(usize, Cut)>,
    ) -> Result<Self, Rejected> {
        let (control, notes, private) = devices(image, notes_sectors);
        if let Some((step, cut)) = cut {
            control.arm_in(step, cut);
        }
        let notes = match Store::open(notes, DEADLINE) {
            Ok(store) => store,
            Err(r) => {
                drop(r.device);
                drop(private);
                return Err(Rejected {
                    error: r.error,
                    control,
                });
            }
        };
        let private = Store::open(private, DEADLINE)
            .unwrap_or_else(|r| panic!("sibling cannot fail: {:?}", r.error));
        Ok(Self {
            gateway: DesktopGateway::new(notes, private, bindings()),
            control,
        })
    }
    fn stop(self) -> Image {
        drop(self.gateway);
        self.control.cold()
    }
}
fn fixture(counter: u64, payload: &[u8]) -> Image {
    // Opaque nonzero owner data stands in for System, registry, legacy AppData,
    // remembered READ policy, old private note and all other physical sectors.
    // Every byte outside Notes is compared after every cut and recovery.
    let mut image: Image = (0..SECTORS)
        .map(|sector| core::array::from_fn(|i| (sector as u8).wrapping_mul(17) ^ i as u8 ^ 0xa5))
        .collect();
    image[32..46].fill([0; 512]);
    image[48..62].fill([0; 512]);
    let (control, notes, private) = devices(image, 14);
    let mut gateway = DesktopGateway::new(
        format(notes, Object::Notes, payload),
        format(private, Object::Private, SEED_PRIVATE),
        bindings(),
    );
    for revision in 1..=counter {
        gateway
            .handle_frame(
                NOTES_RW,
                &Request::Replace {
                    counter: revision,
                    payload: Payload::new(payload).unwrap(),
                }
                .encode(),
                DEADLINE,
            )
            .unwrap();
    }
    drop(gateway);
    control.cold()
}
fn read(gateway: &mut Gateway, route: u64) -> Result<(u64, Payload), FileError<Fault>> {
    let response = gateway.handle_frame(route, &Request::Read.encode(), DEADLINE)?;
    let Response::Read { counter, payload } = Response::decode(&response.encode()).unwrap() else {
        panic!("Read must return actual file contents")
    };
    Ok((counter, payload))
}
fn open_editor(gateway: &mut Gateway) -> Editor {
    let (counter, payload) = read(gateway, NOTES_RW).unwrap();
    let mut editor = Editor::new();
    editor
        .open(Choice::Notes, Access::Edit, counter, &payload)
        .unwrap();
    editor
}
#[derive(Debug, PartialEq, Eq)]
enum SaveFailed {
    Replace,
    Readback,
}
fn save(gateway: &mut Gateway, editor: &mut Editor, proposal: Proposal) -> Result<(), SaveFailed> {
    let response = match gateway.handle_frame(NOTES_RW, &proposal.request().encode(), DEADLINE) {
        Ok(response) => Response::decode(&response.encode()).unwrap(),
        Err(error) => {
            assert_eq!(error.code(), ErrorCode::Io);
            assert_eq!(
                editor.acknowledge(Response::Error { code: error.code() }),
                Err(EditorError::Reply)
            );
            return Err(SaveFailed::Replace);
        }
    };
    editor.acknowledge(response).unwrap();
    assert_eq!(editor.snapshot().state, State::Readback);
    match read(gateway, NOTES_RW) {
        Ok((counter, payload)) => editor.readback(counter, &payload).unwrap(),
        Err(error) => {
            assert_eq!(error.code(), ErrorCode::Io);
            editor.failed(Feedback::Storage);
            return Err(SaveFailed::Readback);
        }
    }
    Ok(())
}
fn blocked(editor: &mut Editor, proposal: Proposal, previous: u64) {
    let before = editor.snapshot();
    assert_eq!(before.state, State::Unavailable);
    assert_eq!(
        before.revision, previous,
        "unconfirmed revision cannot advance"
    );
    assert_eq!(before.text, proposal.text);
    assert!(before.dirty);
    assert_eq!(editor.pending(), Some(proposal));
    assert_eq!(editor.prepare_save(), Err(EditorError::Uncertain));
    assert_eq!(editor.insert("invented retry"), Err(EditorError::Uncertain));
    assert_eq!(editor.navigate(Navigation::Close), Err(EditorError::Busy));
    assert_eq!(editor.closed(), Err(EditorError::State));
    assert_eq!(editor.snapshot(), before);
    editor.snapshot().valid().unwrap();
}
fn unchanged_outside_notes(original: &Image, current: &Image) {
    assert_eq!(current.len(), original.len());
    assert_eq!(&current[..32], &original[..32]);
    assert_eq!(&current[46..], &original[46..]);
}
fn sha(image: &Image) -> String {
    let mut hash = Sha256::new();
    for sector in image {
        hash.update(sector);
    }
    format!("{:x}", hash.finalize())
}

// Independent cold observer: recovery must already have finished. This device
// refuses every write/flush, so observing a prepared state cannot silently fix it.
struct Observer<'a> {
    image: &'a Image,
    mutations: Rc<RefCell<usize>>,
}
impl SectorIo for Observer<'_> {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        14
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), Fault> {
        if lba >= 14 {
            return Err(Fault::Bounds);
        }
        *out = self.image[32 + lba as usize];
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> Result<(), Fault> {
        *self.mutations.borrow_mut() += 1;
        Err(Fault::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> Result<(), Fault> {
        *self.mutations.borrow_mut() += 1;
        Err(Fault::ReadOnly)
    }
}
fn observed(image: &Image) -> (u64, u64, Vec<u8>, u64) {
    let mutations = Rc::new(RefCell::new(0));
    let device = Observer {
        image,
        mutations: mutations.clone(),
    };
    let mut store = Store::open(device, DEADLINE)
        .unwrap_or_else(|r| panic!("independent read-only observation: {:?}", r.error));
    let mut bytes = [0; 256];
    let n = store
        .read_mutable(ObjectId::user_data(), &mut bytes, DEADLINE)
        .unwrap();
    let envelope = Envelope::decode(&bytes[..n]).unwrap();
    assert_eq!(*mutations.borrow(), 0);
    (
        envelope.counter(),
        envelope.global_operation(),
        envelope.payload().to_vec(),
        store.next_operation().unwrap().get(),
    )
}

#[test]
fn every_save_and_readback_cut_preserves_proposal_until_explicit_recovery() {
    let mut replace_failures = 0;
    let mut readback_failures = 0;
    let mut old_recoveries = 0;
    let mut new_recoveries = 0;
    let mut boundaries = Vec::new();
    // The second baseline has already reused the eight-slot Store journal.
    for previous in [0, 12] {
        let original = fixture(previous, OLD);
        let mut complete = Mounted::open(original.clone());
        let mut editor = open_editor(&mut complete.gateway);
        editor.insert(NEW).unwrap();
        let proposal = editor.prepare_save().unwrap();
        let start = complete.control.trace().len();
        save(&mut complete.gateway, &mut editor, proposal).unwrap();
        assert_eq!(editor.snapshot().state, State::Saved);
        let trace = complete.control.trace()[start..].to_vec();
        assert!(trace.contains(&Io::Write) && trace.contains(&Io::Flush));
        let complete_image = complete.stop();
        unchanged_outside_notes(&original, &complete_image);
        assert_eq!(
            observed(&complete_image),
            (
                previous + 1,
                previous + 1,
                proposal.text.as_bytes().to_vec(),
                previous + 2
            )
        );
        boundaries.push(trace.len());
        for step in 1..=trace.len() {
            for cut in CUTS {
                let mut mounted = Mounted::open(original.clone());
                let mut editor = open_editor(&mut mounted.gateway);
                editor.insert(NEW).unwrap();
                assert_eq!(editor.prepare_save().unwrap(), proposal);
                mounted.control.arm_in(step, cut);
                let failed = save(&mut mounted.gateway, &mut editor, proposal)
                    .expect_err("every enumerated cut must execute");
                match failed {
                    SaveFailed::Replace => replace_failures += 1,
                    SaveFailed::Readback => readback_failures += 1,
                }
                blocked(&mut editor, proposal, previous);
                let counts = mounted.control.counts();
                // Even a caller bypassing the editor cannot reuse a poisoned
                // File/Store owner or cause a second backend operation.
                let error = mounted
                    .gateway
                    .handle_frame(NOTES_RW, &proposal.request().encode(), DEADLINE)
                    .unwrap_err();
                assert_eq!(error.code(), ErrorCode::NeedsRecovery);
                assert_eq!(mounted.control.counts(), counts);
                let interrupted = mounted.stop();
                unchanged_outside_notes(&original, &interrupted);

                // This is an explicit stopped-owner cold recovery. The editor
                // remains unavailable; reopening a service does not ACK its save.
                let mut recovered = Mounted::open(interrupted);
                let (counter, payload) = read(&mut recovered.gateway, NOTES_RO).unwrap();
                let already_committed = counter == proposal.counter;
                if already_committed {
                    new_recoveries += 1;
                    assert_eq!(payload.as_slice(), proposal.text.as_bytes());
                } else {
                    old_recoveries += 1;
                    assert_eq!((counter, payload.as_slice()), (previous, OLD));
                }
                if failed == SaveFailed::Readback {
                    assert!(already_committed, "a successful Replace ACK was durable");
                }
                blocked(&mut editor, proposal, previous);
                // Service-level recovery uses the exact retained intent, once.
                // It is not an automatic editor retry or a fresh-counter retry.
                assert_eq!(
                    recovered.gateway.handle_frame(
                        NOTES_RW,
                        &proposal.request().encode(),
                        DEADLINE
                    ),
                    Ok(Response::Replaced {
                        counter: proposal.counter,
                        replayed: already_committed,
                    })
                );
                let counts = recovered.control.counts();
                assert_eq!(
                    recovered.gateway.handle_frame(
                        NOTES_RW,
                        &proposal.request().encode(),
                        DEADLINE
                    ),
                    Ok(Response::Replaced {
                        counter: proposal.counter,
                        replayed: true,
                    })
                );
                let after_replay = recovered.control.counts();
                assert_eq!((after_replay.1, after_replay.2), (counts.1, counts.2));
                let mut fresh = open_editor(&mut recovered.gateway);
                assert_eq!(fresh.snapshot().state, State::Saved);
                assert_eq!(fresh.snapshot().text, proposal.text);
                fresh.closed().unwrap();
                blocked(&mut editor, proposal, previous);
                let final_image = recovered.stop();
                unchanged_outside_notes(&original, &final_image);
                assert_eq!(
                    observed(&final_image),
                    (
                        previous + 1,
                        previous + 1,
                        proposal.text.as_bytes().to_vec(),
                        previous + 2
                    )
                );
            }
        }
    }
    assert!(replace_failures > 0 && readback_failures > 0);
    assert!(old_recoveries > 0 && new_recoveries > 0);
    println!(
        "{}",
        json!({"scope":"cross-layer model, no VM/device/IPC claim", "save_io_boundaries":boundaries,
            "cut_modes":3,"replace_failures":replace_failures,"readback_failures":readback_failures,
            "old_before_explicit_same_intent_recovery":old_recoveries,
            "new_before_explicit_same_intent_recovery":new_recoveries,
            "unchanged_nonselected_bytes_per_case":(SECTORS - 14) * 512})
    );
}

#[test]
fn every_recovery_cut_retains_owner_bytes_and_the_same_pending_intent() {
    let original = fixture(12, OLD);
    let mut complete = Mounted::open(original.clone());
    let mut editor = open_editor(&mut complete.gateway);
    editor.insert(NEW).unwrap();
    let proposal = editor.prepare_save().unwrap();
    let start = complete.control.trace().len();
    save(&mut complete.gateway, &mut editor, proposal).unwrap();
    let prepare_flush = complete.control.trace()[start..]
        .iter()
        .position(|io| *io == Io::Flush)
        .unwrap()
        + 1;
    drop(complete);
    let mut interrupted = Mounted::open(original.clone());
    let mut owner = open_editor(&mut interrupted.gateway);
    owner.insert(NEW).unwrap();
    assert_eq!(owner.prepare_save().unwrap(), proposal);
    interrupted.control.arm_in(prepare_flush, Cut::After);
    assert_eq!(
        save(&mut interrupted.gateway, &mut owner, proposal),
        Err(SaveFailed::Replace)
    );
    blocked(&mut owner, proposal, 12);
    let prepared = interrupted.stop();
    unchanged_outside_notes(&original, &prepared);
    let recovered = Mounted::open(prepared.clone());
    let trace = recovered.control.trace();
    assert!(trace.contains(&Io::Write) && trace.contains(&Io::Flush));
    let expected = recovered.stop();
    assert_eq!(
        observed(&expected),
        (13, 13, proposal.text.as_bytes().to_vec(), 14)
    );
    let mut cases = 0;
    for step in 1..=trace.len() {
        for cut in CUTS {
            let rejected = match Mounted::try_open(prepared.clone(), 14, Some((step, cut))) {
                Ok(_) => panic!("recovery cut {step} {cut:?} did not execute"),
                Err(rejected) => rejected,
            };
            assert_eq!(rejected.error, StoreError::Io(Fault::Power));
            let interrupted_again = rejected.control.cold();
            unchanged_outside_notes(&original, &interrupted_again);
            blocked(&mut owner, proposal, 12);
            let mut reopened = Mounted::open(interrupted_again);
            let counts = reopened.control.counts();
            assert_eq!(
                reopened
                    .gateway
                    .handle_frame(NOTES_RW, &proposal.request().encode(), DEADLINE),
                Ok(Response::Replaced {
                    counter: 13,
                    replayed: true,
                })
            );
            let after = reopened.control.counts();
            assert_eq!((counts.1, counts.2), (after.1, after.2));
            let final_image = reopened.stop();
            unchanged_outside_notes(&original, &final_image);
            assert_eq!(
                observed(&final_image),
                (13, 13, proposal.text.as_bytes().to_vec(), 14)
            );
            let cold_again = Mounted::open(final_image.clone()).stop();
            assert_eq!(cold_again, final_image, "completed recovery is idempotent");
            cases += 1;
        }
    }
    println!(
        "{}",
        json!({"scope":"cross-layer model, no VM/device/IPC claim", "recovery_io_boundaries":trace.len(),
            "actual_recovery_interruptions":cases,"retained_client_counter":13,
            "final_disk_sha256":sha(&expected),"owner_proposal_remains_unavailable":true})
    );
}

#[test]
fn a_lost_commit_or_readback_response_never_turns_uncertainty_into_saved() {
    let original = fixture(12, OLD);
    for after_readback in [false, true] {
        let mut mounted = Mounted::open(original.clone());
        let mut editor = open_editor(&mut mounted.gateway);
        editor.insert(NEW).unwrap();
        let proposal = editor.prepare_save().unwrap();
        let ack = mounted
            .gateway
            .handle_frame(NOTES_RW, &proposal.request().encode(), DEADLINE)
            .unwrap();
        assert_eq!(
            ack,
            Response::Replaced {
                counter: 13,
                replayed: false
            }
        );
        if after_readback {
            editor.acknowledge(ack).unwrap();
            let (counter, payload) = read(&mut mounted.gateway, NOTES_RW).unwrap();
            assert_eq!(counter, 13);
            assert_eq!(payload.as_slice(), proposal.text.as_bytes());
            // Backend finished successfully, but its reply was lost at transport.
            // The real actor must quarantine its frame; this model proves only
            // that the state machine cannot publish or retry the lost result.
        }
        editor.failed(Feedback::Uncertain);
        blocked(&mut editor, proposal, 12);
        let image = mounted.stop();
        unchanged_outside_notes(&original, &image);
        assert_eq!(
            observed(&image),
            (13, 13, proposal.text.as_bytes().to_vec(), 14)
        );
        let mut restarted = Mounted::open(image);
        let fresh = open_editor(&mut restarted.gateway);
        assert_eq!(fresh.snapshot().text, proposal.text);
        blocked(&mut editor, proposal, 12);
    }
}

#[test]
fn full_document_capacity_refuses_without_io_or_truncation_then_saves_exact_length() {
    let original = fixture(12, &[b'x'; 224]);
    let mut mounted = Mounted::open(original.clone());
    let mut editor = open_editor(&mut mounted.gateway);
    let before = editor.snapshot();
    let counts = mounted.control.counts();
    assert_eq!(editor.insert("y"), Err(EditorError::Full));
    assert_eq!(editor.snapshot().text, before.text);
    assert_eq!(editor.snapshot().cursor, before.cursor);
    assert_eq!(editor.snapshot().revision, before.revision);
    assert_eq!(editor.snapshot().feedback, Feedback::Full);
    assert_eq!(editor.snapshot().state, State::Saved);
    assert_eq!(editor.prepare_save(), Err(EditorError::State));
    assert_eq!(editor.pending(), None);
    assert_eq!(mounted.control.counts(), counts);
    assert_eq!(Payload::new(&[b'y'; 225]), Err(DecodeError::Payload));
    let mut oversized = Request::Replace {
        counter: 13,
        payload: Payload::new(&[b'y'; 224]).unwrap(),
    }
    .encode();
    oversized[12..14].copy_from_slice(&225u16.to_le_bytes());
    assert_eq!(
        mounted.gateway.handle_frame(NOTES_RW, &oversized, DEADLINE),
        Err(FileError::Malformed(DecodeError::Payload))
    );
    assert_eq!(mounted.control.counts(), counts);
    let unchanged = mounted.stop();
    assert_eq!(unchanged, original);
    let mut mounted = Mounted::open(unchanged);
    let mut editor = open_editor(&mut mounted.gateway);
    editor.backspace().unwrap();
    let before = editor.snapshot();
    let counts = mounted.control.counts();
    assert_eq!(editor.insert("é"), Err(EditorError::Full));
    assert_eq!(editor.snapshot().text, before.text);
    assert_eq!(editor.snapshot().cursor, before.cursor);
    assert_eq!(mounted.control.counts(), counts);
    editor.backspace().unwrap();
    editor.insert("é").unwrap();
    let proposal = editor.prepare_save().unwrap();
    assert_eq!(proposal.text.len(), 224);
    save(&mut mounted.gateway, &mut editor, proposal).unwrap();
    assert_eq!(editor.snapshot().state, State::Saved);
    let image = mounted.stop();
    unchanged_outside_notes(&original, &image);
    assert_eq!(
        observed(&image),
        (13, 13, proposal.text.as_bytes().to_vec(), 14)
    );
}

#[test]
fn undersized_media_refuses_without_reads_writes_format_or_owner_data_loss() {
    let original = fixture(12, OLD);
    let rejected = match Mounted::try_open(original.clone(), 13, None) {
        Ok(_) => panic!("thirteen sectors must not admit a Store"),
        Err(rejected) => rejected,
    };
    assert_eq!(rejected.error, StoreError::Capacity);
    assert_eq!(rejected.control.counts(), (0, 0, 0));
    let image = rejected.control.cold();
    assert_eq!(image, original);
    let mut restored = Mounted::open(image);
    let editor = open_editor(&mut restored.gateway);
    assert_eq!(editor.snapshot().revision, 12);
    assert_eq!(editor.snapshot().text.as_bytes(), OLD);
    assert_eq!(restored.stop(), original);
}
