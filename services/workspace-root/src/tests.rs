extern crate std;
use super::*;
use ev_workspace_shell::Layer;
use policy::Policy;

#[test]
fn escape_save_cancellation_is_scoped_to_the_focused_saving_editor() {
    use ev_workspace_client::ui::{Command, EDITOR_CANCEL_SAVE_ACTION, State};
    let mut states = [Some(State::Saving); 4];
    for focused in [None, Some(0), Some(3), Some(4), Some(usize::MAX)] {
        assert_eq!(policy::save_cancel_command(focused, &states), None);
    }
    for index in [1, 2] {
        assert_eq!(
            policy::save_cancel_command(Some(index), &states),
            Some(Command::Activate(EDITOR_CANCEL_SAVE_ACTION))
        );
        // It remains a cancellation-specific command even if the App finishes
        // Save before receiving it; the App must never interpret it as Close.
        assert_ne!(EDITOR_CANCEL_SAVE_ACTION, 4);
        for state in [
            None,
            Some(State::NoFile),
            Some(State::Loading),
            Some(State::Saved),
            Some(State::Dirty),
            Some(State::Conflict),
            Some(State::Uncertain),
        ] {
            states[index] = state;
            assert_eq!(policy::save_cancel_command(Some(index), &states), None);
        }
        states[index] = Some(State::Saving);
    }
}

fn actor(index: usize) -> Actor {
    Actor {
        control: 100 + index as u64,
        identity: Identity {
            process: 10 + index as u64,
            thread: 20 + index as u64,
            registered: 1,
        },
        ready: true,
        mapping_epoch: 1,
        failed: false,
    }
}
#[test]
fn full_owner_instances_and_geometry_share_the_model() {
    let mut p = Policy::new(actor(5).identity, actor(6).identity).unwrap();
    for i in 0..4 {
        p.install(i, actor(i)).unwrap();
    }
    p.focus(1).unwrap();
    assert_eq!(p.focused(), Some(1));
    let bounds = p
        .geometry(
            1,
            ev_userspace_contract::root_v5::display_control::Bounds {
                x: -900,
                y: 900,
                width: 999,
                height: 999,
            },
        )
        .unwrap();
    assert_eq!(bounds.width, 320);
    assert_eq!(bounds.height, 180);
    assert_eq!(bounds.x, 0);
    assert_eq!(bounds.y, 282);
    assert_eq!(p.hit(10, 280), Some((1, true)));
    let old = p.ids[1].unwrap();
    p.retire(1, actor(1).identity).unwrap();
    let mut replacement = actor(1);
    replacement.identity.process = 500;
    p.install(1, replacement).unwrap();
    assert_ne!(p.ids[1].unwrap(), old);
    assert!(p.desktop.window(old).is_err());
    p.layer(Layer::AbsoluteAccess).unwrap();
    assert!(p.desktop.view().show_owner_controls);
    assert!(p.desktop.pending_challenge().is_none());
    let files = p
        .geometry(
            0,
            ev_userspace_contract::root_v5::display_control::Bounds {
                x: 0,
                y: 91,
                width: 1,
                height: 1,
            },
        )
        .unwrap();
    assert_eq!((files.width, files.height), (160, 100));
}
#[test]
fn closed_graph_routes_do_not_confuse_owners_or_core_ready() {
    for i in 0..4 {
        let child = app_child(i).unwrap();
        assert_eq!(child_slot(child).unwrap().index(), i);
        assert_eq!(control_channel(child).unwrap().receiver(), child);
        assert_eq!(inbox_channel(i).unwrap().receiver(), child);
    }
    assert_eq!(
        ready_bytes(ev_userspace_contract::root_v5::graph::Child::Display),
        Some(*b"EVDPRDY5")
    );
    assert_eq!(ready_bytes(app_child(1).unwrap()), None);
    assert!(app_child(4).is_none());
}

#[test]
fn protected_renderer_keeps_extent_and_full_escaped_name_in_bounded_rows() {
    use ev_graphics::{Color, Pixels};
    use ev_userspace_contract::workspace::{Entry, EntryState, Kind, Name, ObjectId};
    struct Sink {
        data: std::vec::Vec<Color>,
    }
    impl Pixels for Sink {
        fn dimensions(&self) -> (usize, usize) {
            (640, 80)
        }
        fn write(&mut self, x: usize, y: usize, c: Color) -> Result<(), ev_graphics::Error> {
            assert!(x < 640 && y < 80);
            self.data[1 + y * 640 + x] = c;
            Ok(())
        }
    }
    let mut sink = Sink {
        data: std::vec![Color(0xabcdef);640*80+2],
    };
    let name = "é".repeat(48);
    let entry = Entry {
        object: ObjectId {
            slot: 256,
            generation: u64::MAX - 1,
        },
        parent: ObjectId {
            slot: 0,
            generation: 1,
        },
        revision: u64::MAX - 1,
        size: 1_048_576,
        kind: Kind::File,
        state: EntryState::Live,
        name: Name::new(name.as_bytes()).unwrap(),
    };
    render::render(
        &mut sink,
        render::View {
            mode: render::Mode::Consent,
            title: b"Exact owner confirmation",
            status: b"Protected",
            refusal: None,
            recipient: Some(render::Recipient {
                editor: 2,
                process: u64::MAX - 1,
                thread: u64::MAX - 2,
                nonce: u64::MAX - 3,
            }),
            entry: Some(entry),
            writable: false,
            layer: 3,
            dataset: [0; 16],
            development: None,
        },
    )
    .unwrap();
    assert_eq!(sink.data[0], Color(0xabcdef));
    assert_eq!(*sink.data.last().unwrap(), Color(0xabcdef));

    let revoke = render::View {
        mode: render::Mode::Revoke,
        title: b"Revoke original Private READ; copied bytes remain",
        status: b"Recorded scope only; no new grant and no deletion of copied bytes",
        refusal: None,
        recipient: Some(render::Recipient {
            editor: 1,
            process: 55,
            thread: 66,
            nonce: 7,
        }),
        entry: Some(entry),
        writable: false,
        layer: 1,
        dataset: [1; 16],
        development: None,
    };
    render::render(&mut sink, revoke).unwrap();
    let first = sink.data.clone();
    let mut changed = [1; 16];
    changed[15] = 2;
    render::render(
        &mut sink,
        render::View {
            dataset: changed,
            ..revoke
        },
    )
    .unwrap();
    let changed_pixels: std::vec::Vec<_> = first
        .iter()
        .zip(&sink.data)
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    assert!(!changed_pixels.is_empty());
    assert!(changed_pixels.iter().all(|index| {
        let (x, y) = ((index - 1) % 640, (index - 1) / 640);
        (504..510).contains(&x) && (11..18).contains(&y)
    }));
    assert_eq!(
        render::dataset_text(changed),
        *b"D=01010101010101010101010101010102"
    );
    assert_eq!(sink.data[0], Color(0xabcdef));
    assert_eq!(*sink.data.last().unwrap(), Color(0xabcdef));
    // Last escaped byte is within row61; full identity/revision has a distinct
    // metadata row, and the confirmation/cancel labels stay in row71.
    assert!(
        sink.data[1 + 61 * 640..1 + 68 * 640]
            .iter()
            .any(|c| *c != ev_graphics::BACKGROUND)
    );
    assert!(sink.data[1 + 71 * 640..1 + 78 * 640].contains(&ev_graphics::ACCENT));
    render::render(
        &mut sink,
        render::View {
            mode: render::Mode::Desktop,
            title: b"Protected diagnostics",
            status: b"Application refused the requested operation",
            refusal: Some(render::Refusal {
                process: u64::MAX,
                thread: u64::MAX - 1,
                observed: u64::MAX - 2,
                count: u64::MAX,
                code: u8::MAX,
            }),
            recipient: None,
            entry: None,
            writable: false,
            layer: 1,
            dataset: [0; 16],
            development: None,
        },
    )
    .unwrap();
    assert!(sink.data[1 + 41 * 640..1 + 48 * 640].contains(&ev_graphics::DANGER));
    assert!(sink.data[1 + 51 * 640..1 + 58 * 640].contains(&ev_graphics::MUTED));
    assert!(
        sink.data[1 + 61 * 640..1 + 68 * 640]
            .iter()
            .all(|c| *c == ev_graphics::BACKGROUND)
    );
    assert_eq!(sink.data[0], Color(0xabcdef));
    assert_eq!(*sink.data.last().unwrap(), Color(0xabcdef));
}
