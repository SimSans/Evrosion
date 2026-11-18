use super::*;
use ev_userspace_contract::workspace as wire;
use ev_workspace_client::{
    TransportError,
    namespace::{self, Link},
};
use ev_workspace_service::{
    Caller, Captured, EndpointId, Gateway, NamespaceBinding, NamespaceDispatch, NamespaceRights,
    Scratch as GatewayScratch,
};
use ev_workspace_store::{Dataset, DatasetId, REQUIRED_SECTORS, Scratch, Sector, SectorIo};
use std::{boxed::Box, cell::RefCell, collections::BTreeMap, rc::Rc, vec, vec::Vec};
const CUT: u64 = 100_000;
#[test]
fn strict_files_v1_profile_preserves_bootstrap_abi_and_rejects_aliases_or_rights_widening() {
    use ev_userspace_contract::{Context, GRANT_BYTES, Grant, HEADER, encode};
    let context = Context {
        epoch: 1,
        incarnation: 9,
        process: 7,
        limits: ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[2],
        manifest: [1; 32],
        authority: [2; 32],
    };
    let specs = [(1, 7), (2, 8), (2, 8), (2, 272), (1, 7), (2, 272), (2, 8)];
    let grants: [Grant; 7] = core::array::from_fn(|i| Grant {
        selector: i as u64 + 1,
        handle: 100 + i as u64,
        kind: specs[i].0,
        rights: specs[i].1,
    });
    let good = encode(context, &grants).unwrap();
    let parsed = Profile::parse(&good).unwrap();
    assert_eq!(parsed.process, 7);
    assert_eq!(parsed.registered_incarnation, 9);
    assert_eq!(parsed.handles[6], 106);
    let mut alias = good;
    alias[HEADER + 4 * GRANT_BYTES + 8..HEADER + 4 * GRANT_BYTES + 16]
        .copy_from_slice(&100u64.to_le_bytes());
    assert!(matches!(Profile::parse(&alias), Err(ProfileError::Roles)));
    let mut widened = grants;
    widened[6].rights |= 64;
    let b = encode(context, &widened).unwrap();
    assert!(matches!(Profile::parse(&b), Err(ProfileError::Roles)));
    let mut wrong = context;
    wrong.limits[1] += 1;
    let b = encode(wrong, &grants).unwrap();
    assert!(matches!(Profile::parse(&b), Err(ProfileError::Limits)));
    assert!(Profile::parse(&good[..335]).is_err());
    let mut reserved = good;
    reserved[143] = 1;
    assert!(Profile::parse(&reserved).is_err());
}
#[derive(Clone)]
struct Memory(Rc<RefCell<BTreeMap<u64, Sector>>>);
impl Memory {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(BTreeMap::new())))
    }
    fn cold(&self) -> Self {
        Self(Rc::new(RefCell::new(self.0.borrow().clone())))
    }
}
impl SectorIo for Memory {
    type Error = ();
    fn sectors(&self) -> u64 {
        REQUIRED_SECTORS
    }
    fn read(&mut self, sector: u64, out: &mut Sector, _: u64) -> Result<(), ()> {
        if sector >= REQUIRED_SECTORS {
            return Err(());
        }
        *out = *self.0.borrow().get(&sector).unwrap_or(&[0; 512]);
        Ok(())
    }
    fn write(&mut self, sector: u64, bytes: &Sector, _: u64) -> Result<(), ()> {
        if sector >= REQUIRED_SECTORS {
            return Err(());
        }
        self.0.borrow_mut().insert(sector, *bytes);
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), ()> {
        Ok(())
    }
}
struct Peer<'a, 'b> {
    gateway: Gateway<'a, 'b, Memory>,
    binding: NamespaceBinding,
}
impl<'a, 'b> Peer<'a, 'b> {
    fn new(mut gateway: Gateway<'a, 'b, Memory>) -> Self {
        let binding = NamespaceBinding {
            endpoint: EndpointId::new(55, 1).unwrap(),
            caller: Caller::new(7, 9).unwrap(),
            lease_epoch: 1,
            directory: ev_workspace_store::ObjectId::ROOT,
            rights: NamespaceRights::Manage,
        };
        gateway.bind_namespace(binding).unwrap();
        Self { gateway, binding }
    }
}
impl Link for Peer<'_, '_> {
    fn now(&mut self) -> Result<u64, TransportError> {
        Ok(1)
    }
    fn exchange(
        &mut self,
        request: wire::Request,
        frame: &[u8; 256],
    ) -> Result<[u8; 256], TransportError> {
        assert_eq!(wire::Request::decode(frame), Ok(request));
        let captured = Captured {
            endpoint: self.binding.endpoint,
            caller: self.binding.caller,
            lease_epoch: self.binding.lease_epoch,
            now: 1,
        };
        match self
            .gateway
            .handle_namespace(captured, frame, 0)
            .map_err(|_| TransportError::Correlation)?
        {
            NamespaceDispatch::Complete { frame } => Ok(frame),
            NamespaceDispatch::Retained => Err(TransportError::Rpc),
        }
    }
}
fn deadline() -> Deadline {
    Deadline::new(8000).unwrap()
}
fn load<L: Link>(browser: &mut Browser, client: &mut Client<L>) {
    for _ in 0..12 {
        if !browser.loading() {
            break;
        }
        browser.step(client, deadline());
    }
    assert!(!browser.loading());
    assert_ne!(browser.status(), Status::Uncertain);
}
fn command<L: Link>(
    browser: &mut Browser,
    client: &mut Client<L>,
    command: Command,
) -> Option<Event> {
    browser.command(client, command, deadline())
}
fn type_name<L: Link>(browser: &mut Browser, client: &mut Client<L>, name: &str) {
    for c in name.chars() {
        command(browser, client, Command::Insert(c));
    }
}
fn select<L: Link>(browser: &mut Browser, client: &mut Client<L>, name: &str) {
    let index = browser
        .entries()
        .position(|e| e.name.as_str() == name)
        .unwrap();
    command(
        browser,
        client,
        Command::Activate(action::SELECT + index as u16),
    );
}

#[test]
fn actual_dataset_gateway_sdk_browser_crud_dynamic_parentage_and_cold_names() {
    let memory = Memory::new();
    let mut store = Box::new(Scratch::empty());
    let mut scratch = Box::new(GatewayScratch::empty());
    let data = Dataset::format_new(
        memory.clone(),
        &mut store,
        DatasetId::new([8; 16]).unwrap(),
        CUT,
    )
    .unwrap_or_else(|_| panic!("format"));
    let mut client = Client::new(Peer::new(Gateway::new(data, &mut scratch)));
    let mut browser = Browser::new();
    load(&mut browser, &mut client);
    assert_eq!(browser.entries().count(), 0);
    command(&mut browser, &mut client, Command::Activate(action::FOLDER));
    type_name(&mut browser, &mut client, "Folder é");
    command(&mut browser, &mut client, Command::Save);
    load(&mut browser, &mut client);
    let folder = browser.selected().unwrap().object;
    command(&mut browser, &mut client, Command::Activate(action::TEXT));
    type_name(&mut browser, &mut client, "draft.txt");
    command(&mut browser, &mut client, Command::Insert('\n'));
    load(&mut browser, &mut client);
    select(&mut browser, &mut client, "draft.txt");
    let file = browser.selected().unwrap().object;
    command(&mut browser, &mut client, Command::Activate(action::RENAME));
    type_name(&mut browser, &mut client, "renamed.txt");
    command(&mut browser, &mut client, Command::Save);
    load(&mut browser, &mut client);
    select(&mut browser, &mut client, "renamed.txt");
    assert_eq!(browser.selected().unwrap().object, file);
    assert_eq!(
        command(&mut browser, &mut client, Command::Activate(action::OPEN)),
        Some(Event::Open)
    );
    assert_eq!(client.state(), ClientState::Ready);
    command(&mut browser, &mut client, Command::Activate(action::MOVE));
    select(&mut browser, &mut client, "Folder é");
    command(
        &mut browser,
        &mut client,
        Command::Navigate {
            key: Navigation::Right,
            extend: false,
        },
    );
    load(&mut browser, &mut client);
    assert_eq!(browser.directory(), folder);
    command(&mut browser, &mut client, Command::Activate(action::APPLY));
    load(&mut browser, &mut client);
    assert_eq!(browser.selected().unwrap().object, file);
    assert_eq!(browser.selected().unwrap().parent, folder);
    command(&mut browser, &mut client, Command::Activate(action::TRASH));
    load(&mut browser, &mut client);
    assert_eq!(browser.selected().unwrap().state, EntryState::Trashed);
    command(
        &mut browser,
        &mut client,
        Command::Activate(action::RESTORE),
    );
    load(&mut browser, &mut client);
    assert_eq!(browser.selected().unwrap().state, EntryState::Live);
    command(&mut browser, &mut client, Command::Activate(action::UP));
    load(&mut browser, &mut client);
    assert_eq!(browser.directory(), ROOT);
    assert_eq!(browser.entries().count(), 1);
    // Host cold-copy model only. Actual endpoint/device retirement is a separate
    // native proof; this test does not infer quiescence from dropping owners.
    drop(client);
    let cold = memory.cold();
    let mut cold_store = Box::new(Scratch::empty());
    let data = Dataset::open(cold, &mut cold_store, CUT).unwrap_or_else(|_| panic!("cold"));
    let mut client = Client::new(Peer::new(Gateway::new(data, &mut scratch)));
    let mut browser = Browser::new();
    load(&mut browser, &mut client);
    assert_eq!(browser.selected().unwrap().name.as_str(), "Folder é");
    command(
        &mut browser,
        &mut client,
        Command::Navigate {
            key: Navigation::Right,
            extend: false,
        },
    );
    load(&mut browser, &mut client);
    let entry = browser.selected().unwrap();
    assert_eq!(entry.object, file);
    assert_eq!(entry.name.as_str(), "renamed.txt");
    assert_eq!(entry.parent, folder);
}
#[test]
fn unsent_names_and_moves_refuse_close_without_changing_text_or_storage() {
    let memory = Memory::new();
    let mut store = Box::new(Scratch::empty());
    let mut scratch = Box::new(GatewayScratch::empty());
    let data = Dataset::format_new(
        memory.clone(),
        &mut store,
        DatasetId::new([8; 16]).unwrap(),
        CUT,
    )
    .unwrap_or_else(|_| panic!("format"));
    let mut client = Client::new(Peer::new(Gateway::new(data, &mut scratch)));
    let mut browser = Browser::new();
    load(&mut browser, &mut client);
    assert_eq!(browser.close(false), Close::Ready);
    command(&mut browser, &mut client, Command::Activate(action::TEXT));
    type_name(&mut browser, &mut client, "unsent.txt");
    let saved = memory.0.borrow().clone();
    assert_eq!(browser.app_state(), ev_workspace_client::ui::State::Dirty);
    assert_eq!(browser.close(false), Close::ConfirmDiscard);
    assert_eq!(browser.name(), "unsent.txt");
    assert_eq!(*memory.0.borrow(), saved);
    assert_eq!(browser.close(true), Close::Ready);
    assert_eq!(browser.name(), "unsent.txt"); // inspection never performs discard
    command(&mut browser, &mut client, Command::Activate(action::CANCEL));
    assert_eq!(browser.close(false), Close::Ready);
    assert_eq!(browser.app_state(), ev_workspace_client::ui::State::Saved);
    assert_eq!(*memory.0.borrow(), saved);
    command(&mut browser, &mut client, Command::Activate(action::TEXT));
    type_name(&mut browser, &mut client, "move-me.txt");
    command(&mut browser, &mut client, Command::Save);
    load(&mut browser, &mut client);
    command(&mut browser, &mut client, Command::Activate(action::MOVE));
    let before_move = memory.0.borrow().clone();
    assert_eq!(browser.close(false), Close::ConfirmDiscard);
    assert_eq!(browser.app_state(), ev_workspace_client::ui::State::Dirty);
    assert_eq!(*memory.0.borrow(), before_move);
}

#[test]
fn real_paged_list_names_are_not_compiled_and_unicode_input_is_scalar_bounded() {
    let memory = Memory::new();
    let mut store = Box::new(Scratch::empty());
    let mut scratch = Box::new(GatewayScratch::empty());
    let mut data = Dataset::format_new(memory, &mut store, DatasetId::new([8; 16]).unwrap(), CUT)
        .unwrap_or_else(|_| panic!("format"));
    for i in 0..19 {
        data.create(
            data.next_operation().unwrap(),
            data.namespace_revision(),
            ev_workspace_store::ObjectId::ROOT,
            ev_workspace_store::Name::new(&std::format!("actual{i}.txt")).unwrap(),
            ev_workspace_store::Kind::File,
            CUT,
        )
        .unwrap();
    }
    let mut client = Client::new(Peer::new(Gateway::new(data, &mut scratch)));
    let mut browser = Browser::new();
    load(&mut browser, &mut client);
    assert_eq!(browser.entries().count(), 8);
    assert_eq!(
        browser.entries().next().unwrap().name.as_str(),
        "actual0.txt"
    );
    command(&mut browser, &mut client, Command::Activate(action::NEXT));
    load(&mut browser, &mut client);
    assert_eq!(browser.entries().count(), 8);
    assert_eq!(
        browser.entries().next().unwrap().name.as_str(),
        "actual8.txt"
    );
    command(&mut browser, &mut client, Command::Activate(action::NEXT));
    load(&mut browser, &mut client);
    assert_eq!(browser.entries().count(), 3);
    assert_eq!(
        browser.entries().next().unwrap().name.as_str(),
        "actual16.txt"
    );
    command(&mut browser, &mut client, Command::Activate(action::PREV));
    load(&mut browser, &mut client);
    assert_eq!(
        browser.entries().next().unwrap().name.as_str(),
        "actual8.txt"
    );
    command(&mut browser, &mut client, Command::Activate(action::TEXT));
    let directory = browser.directory();
    command(
        &mut browser,
        &mut client,
        Command::Navigate {
            key: Navigation::Left,
            extend: false,
        },
    );
    assert_eq!(browser.directory(), directory);
    type_name(&mut browser, &mut client, &"é".repeat(48));
    assert_eq!(browser.name().len(), 96);
    command(&mut browser, &mut client, Command::Insert('x'));
    assert_eq!(browser.name().len(), 96);
    assert_eq!(browser.status(), Status::Name);
    command(
        &mut browser,
        &mut client,
        Command::Navigate {
            key: Navigation::Backspace,
            extend: false,
        },
    );
    assert_eq!(browser.name().len(), 94);
    assert!(browser.name().is_char_boundary(94));
    command(&mut browser, &mut client, Command::Insert('/'));
    assert_eq!(browser.name().len(), 94);
    command(&mut browser, &mut client, Command::SelectAll);
    type_name(&mut browser, &mut client, "replacement.txt");
    assert_eq!(browser.name(), "replacement.txt");
}

struct PixelsMemory {
    width: usize,
    height: usize,
    bytes: Vec<u32>,
    writes: usize,
}
impl Pixels for PixelsMemory {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), GraphicsError> {
        assert!(x < self.width && y < self.height);
        self.bytes[y * self.width + x] = color.0;
        self.writes += 1;
        Ok(())
    }
}
#[test]
fn actual_viewport_clips_all_pixels_and_hit_coordinates_and_carries_no_capabilities() {
    let browser = Browser::new();
    for (width, height) in [(1, 1), (29, 40), (160, 90), (320, 180), (320, 200)] {
        let mut p = PixelsMemory {
            width,
            height,
            bytes: vec![0; width * height],
            writes: 0,
        };
        render(&mut p, &browser, true).unwrap();
        assert!(p.writes >= width * height);
        assert_eq!(hit_test(width, height, width, 0), None);
        assert_eq!(hit_test(width, height, 0, height), None);
    }
    assert_eq!(hit_test(320, 180, 2, 2), Some(action::UP));
    assert_eq!(hit_test(320, 180, 319, 39), Some(action::NEXT));
    assert_eq!(hit_test(320, 180, 205, 49), Some(action::APPLY));
    assert_eq!(hit_test(320, 180, 280, 49), Some(action::CANCEL));
    assert_eq!(hit_test(320, 180, 20, 69), Some(action::SELECT));
    let mut p = PixelsMemory {
        width: 321,
        height: 180,
        bytes: vec![0; 321 * 180],
        writes: 0,
    };
    assert_eq!(
        render(&mut p, &browser, false),
        Err(GraphicsError::Geometry)
    );
    assert_eq!(p.writes, 0);
}
struct Failed {
    calls: Rc<RefCell<usize>>,
}
impl Link for Failed {
    fn now(&mut self) -> Result<u64, TransportError> {
        Ok(1)
    }
    fn exchange(&mut self, _: wire::Request, _: &[u8; 256]) -> Result<[u8; 256], TransportError> {
        *self.calls.borrow_mut() += 1;
        Err(TransportError::Rpc)
    }
}
#[test]
fn app_freezes_name_and_operations_when_namespace_reply_is_uncertain() {
    let calls = Rc::new(RefCell::new(0));
    let mut client = namespace::Client::new(Failed {
        calls: calls.clone(),
    });
    let mut browser = Browser::new();
    browser.step(&mut client, deadline());
    assert_eq!(browser.status(), Status::Uncertain);
    assert_eq!(browser.close(false), Close::RecoveryRequired);
    assert_eq!(browser.close(true), Close::RecoveryRequired);
    assert_eq!(
        browser.app_state(),
        ev_workspace_client::ui::State::Uncertain
    );
    for command in [
        Command::Activate(action::TEXT),
        Command::Insert('x'),
        Command::Activate(action::REFRESH),
        Command::Save,
    ] {
        browser.command(&mut client, command, deadline());
    }
    assert_eq!(*calls.borrow(), 1);
    assert_eq!(browser.name(), "");
    assert_eq!(client.state(), ClientState::Uncertain);
}

fn semantic_header(page: u8, nonce: u32) -> ev_workspace_client::semantic::Header {
    ev_workspace_client::semantic::Header {
        nonce,
        page,
        pages: 3,
        model: 0x1_0000_0001,
        view: 0x2_0000_0002,
        frame: 0x3_0000_0003,
        mapping_epoch: 0x4_0000_0004,
        width: 160,
        height: 100,
        keyboard: 0,
        modal: 0,
    }
}
fn semantic_decode(
    mut p: ev_workspace_client::semantic::Publisher,
    page: u8,
    nonce: u32,
) -> ev_workspace_client::semantic::Snapshot {
    use ev_workspace_client::semantic as a1;
    let mut r = a1::Receiver::new();
    r.request(page, nonce).unwrap();
    while let Some(f) = p.next() {
        r.push(f).unwrap();
        p.sent(f).unwrap();
    }
    let mut out = a1::Snapshot::EMPTY;
    r.candidate(&mut out).unwrap();
    out
}
#[test]
fn semantic_pages_keep_sixteen_bound_name_focus_and_disabled_namespace_actions() {
    use ev_workspace_client::semantic as a1;
    let mut browser = Browser::new();
    for page in 0..3 {
        let mut p = a1::Publisher::new();
        semantic::publish(&mut p, semantic_header(page, 7), &browser, true).unwrap();
        let tree = semantic_decode(p, page, 7);
        assert!(tree.nodes().len() <= 16);
        assert!(
            tree.nodes()
                .iter()
                .filter(|n| n.role == a1::Role::Button)
                .all(|n| n.flags == 1 && n.actions == 0)
        );
        assert_eq!(tree.header().view, 0x2_0000_0002);
    }
    // Native loading has completed; an actual name-editing view fits all visible
    // controls and the focused input on page1 without widening the bound.
    browser.load = None;
    browser.status = Status::Editing;
    browser.mode = Mode::NewFile;
    for c in "α".repeat(48).chars() {
        browser.input(c);
    }
    let mut p = a1::Publisher::new();
    semantic::publish(&mut p, semantic_header(1, 9), &browser, true).unwrap();
    let tree = semantic_decode(p, 1, 9);
    assert_eq!(tree.nodes().len(), 16);
    assert_eq!(tree.header().keyboard, 5);
    let name = tree.nodes().iter().find(|n| n.local == 5).unwrap();
    assert_eq!(
        name.value,
        a1::Value::TextRange {
            revision: tree.header().view,
            offset: 0,
            length: 96,
            total: 96
        }
    );
    assert_eq!(semantic::button(&browser, 19), None);
    assert_eq!(semantic::button(&browser, 26), Some(action::APPLY));
    assert_eq!(semantic::row_actions(&browser, 0, 8), 0);
    assert_eq!(hit_test(160, 100, 145, 95), Some(action::REFRESH));
}
#[test]
fn semantic_transport_waits_for_commit_present_and_explicit_range_abort() {
    use ev_workspace_client::semantic::{self as a1, operation as op};
    let browser = Browser::new();
    let h = semantic_header(0, 11);
    let mut s = semantic::Session::new();
    s.request(
        a1::Request::Snapshot { page: 0, nonce: 11 },
        h,
        true,
        &browser,
        false,
    );
    let binding = op::Binding {
        snapshot_nonce: 11,
        model: h.model,
        view: h.view,
        frame: h.frame,
        mapping_epoch: h.mapping_epoch,
        text_revision: h.view,
    };
    assert_eq!(s.bound_page(binding), None);
    while let Some(f) = s.snapshot_next() {
        assert_eq!(s.snapshot_next(), Some(f));
        if f.field != a1::COMMIT {
            assert_eq!(s.bound_page(binding), None);
        }
        s.snapshot_sent(f).unwrap();
    }
    assert_eq!(s.bound_page(binding), Some(0));
    assert_eq!(
        s.bound_page(op::Binding {
            snapshot_nonce: 12,
            ..binding
        }),
        None
    );
    let request = op::Request {
        nonce: 31,
        node: 5,
        binding,
        kind: op::Kind::Range {
            kind: op::RangeKind::AccessibleLabel,
            offset: 0,
            length: 16,
        },
    };
    for i in 0..18 {
        let got = s.operation(request.frame(i).unwrap().unwrap());
        assert_eq!(got, if i == 17 { Some(request) } else { None });
    }
    s.range(31, 5, op::RangeKind::AccessibleLabel, "αβ")
        .unwrap();
    let first = s.operation_next(true, false, h.frame).unwrap();
    assert_eq!(s.operation_next(true, false, h.frame), Some(first));
    s.operation_sent(first).unwrap();
    assert!(
        s.operation(a1::Frame {
            field: op::ABORT,
            word: 31
        })
        .is_none()
    );
    let ack = s.operation_next(true, false, h.frame).unwrap();
    assert_eq!(
        ack,
        a1::Frame {
            field: op::ABORT_ACK,
            word: 31
        }
    );
    s.operation_sent(ack).unwrap();
    s.after_present(32, h.frame);
    assert!(s.operation_next(false, false, h.frame + 1).is_none());
    assert!(s.operation_next(true, true, h.frame + 1).is_none());
    assert!(s.operation_next(true, false, h.frame).is_none());
    assert_eq!(
        s.operation_next(true, false, h.frame + 1),
        Some(op::terminal(32, Ok(())))
    );
}
#[test]
fn rename_input_cannot_select_or_enter_a_different_row_before_apply() {
    let memory = Memory::new();
    let mut store = Box::new(Scratch::empty());
    let mut scratch = Box::new(GatewayScratch::empty());
    let data = Dataset::format_new(memory, &mut store, DatasetId::new([33; 16]).unwrap(), CUT)
        .unwrap_or_else(|_| panic!("format owned fixture"));
    let mut client = Client::new(Peer::new(Gateway::new(data, &mut scratch)));
    let mut browser = Browser::new();
    load(&mut browser, &mut client);
    for name in ["first", "second"] {
        command(&mut browser, &mut client, Command::Activate(action::TEXT));
        type_name(&mut browser, &mut client, name);
        command(&mut browser, &mut client, Command::Save);
        load(&mut browser, &mut client);
    }
    select(&mut browser, &mut client, "first");
    let original = browser.selected().unwrap().object;
    command(&mut browser, &mut client, Command::Activate(action::RENAME));
    type_name(&mut browser, &mut client, "renamed");
    command(
        &mut browser,
        &mut client,
        Command::Activate(action::SELECT + 1),
    );
    command(
        &mut browser,
        &mut client,
        Command::Activate(action::ENTER + 1),
    );
    assert_eq!(browser.selected().unwrap().object, original);
    assert_eq!(browser.mode(), Mode::Rename(original));
    assert_eq!(browser.name(), "renamed");
    command(&mut browser, &mut client, Command::Save);
    load(&mut browser, &mut client);
    select(&mut browser, &mut client, "renamed");
    assert_eq!(browser.selected().unwrap().object, original);
    assert_eq!(semantic::row_actions(&browser, usize::MAX, 8), 0);
}
