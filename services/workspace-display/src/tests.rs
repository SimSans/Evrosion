extern crate std;
use super::*;
use core::cell::Cell;
use ev_graphics::{Color, Pixels};
use ev_userspace_contract::root_v5::{child, graph::Child, surface::Registration};
use ev_workspace_shell::composition::Raster;
use std::{vec, vec::Vec};

const SENTINEL: Color = Color(0x123456);
#[test]
fn live_credit_checks_refuse_cancellation_expiry_and_noncanonical_replies() {
    let origin = root();
    let live = CreditStatus {
        status: 0,
        value: 0,
        capability: 0,
        serial: 0,
    };
    assert!(origin.live_checkpoint(live, origin.deadline - 1));
    assert!(origin.kernel_checkpoint(live));
    assert!(!origin.live_checkpoint(live, origin.deadline));
    assert!(!origin.live_checkpoint(live, origin.deadline + 1));
    for reply in [
        CreditStatus { status: 1, ..live },
        CreditStatus { value: 1, ..live }, // cancelled
        CreditStatus { value: 2, ..live }, // expired
        CreditStatus { value: 3, ..live }, // peer died
        CreditStatus {
            capability: 1,
            ..live
        },
        CreditStatus { serial: 1, ..live },
    ] {
        assert!(!origin.live_checkpoint(reply, 1));
        assert!(!origin.kernel_checkpoint(reply));
    }
    for origin in [
        Origin {
            status: 1,
            ..origin
        },
        Origin {
            deadline: 0,
            ..origin
        },
        Origin {
            deadline: u64::MAX,
            ..origin
        },
    ] {
        assert!(!origin.live_checkpoint(live, 1));
        assert!(!origin.kernel_checkpoint(live));
    }
}
fn root() -> Origin {
    Origin {
        process: 90,
        thread: 91,
        incarnation: 0,
        call_epoch: 1,
        serial: 2,
        endpoint: 300,
        deadline: 10000,
        status: 0,
    }
}
fn owner(slot: Slot) -> Origin {
    if slot == Slot::ProtectedRoot {
        return root();
    }
    let i = slot.index() as u64;
    Origin {
        process: 10 + i,
        thread: 30 + i,
        incarnation: 50 + i,
        call_epoch: 1,
        serial: 2,
        endpoint: 301,
        deadline: 10000,
        status: 0,
    }
}
fn authority() -> ControlAuthority {
    let bytes = child::encode_profile(
        Child::Display,
        ev_userspace_contract::Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: Child::Display.limits(),
            manifest: [1; 32],
            authority: [2; 32],
        },
        &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109],
    )
    .unwrap();
    ControlAuthority::from_validated_bootstrap(
        &child::Profile::parse(Child::Display, &bytes).unwrap(),
    )
    .unwrap()
}
fn control(state: &mut State, request: u64, command: Command) -> Result<ControlEffect, Error> {
    state.control(
        authority().capture(109, root().serial, root()).unwrap(),
        Envelope { request, command },
    )
}
fn window(slot: Slot) -> Window {
    let o = owner(slot);
    let i = slot.index();
    Window {
        slot,
        registration: Registration {
            sequence: 1,
            source_role: slot.source(),
            producer: slot.producer(),
            instance: slot.instance(),
            process: o.process,
            thread: o.thread,
            incarnation: if slot == Slot::ProtectedRoot {
                92
            } else {
                o.incarnation
            },
            surface_object: slot.source().selector(),
            surface_generation: o.process,
            mapping_epoch: 1,
        },
        bounds: match slot {
            Slot::ProtectedRoot => control::Bounds {
                x: 0,
                y: 0,
                width: 640,
                height: 80,
            },
            Slot::Shell => control::Bounds {
                x: 0,
                y: 462,
                width: 640,
                height: 18,
            },
            _ => control::Bounds {
                x: if i.is_multiple_of(2) { 0 } else { 320 },
                y: if i < 2 { 91 } else { 282 },
                width: 320,
                height: 180,
            },
        },
        z: i as u8,
        visible: true,
        view_revision: 1,
        strict_view: false,
        focused: slot == Slot::Files,
    }
}
fn scene() -> State {
    let mut state = State::new(2).unwrap();
    control(
        &mut state,
        1,
        Command::Begin {
            transaction: 1,
            model_revision: 1,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
        },
    )
    .unwrap();
    for (i, slot) in control::SLOTS.into_iter().enumerate() {
        control(
            &mut state,
            2 + i as u64,
            Command::Register {
                transaction: 1,
                window: window(slot),
            },
        )
        .unwrap();
    }
    let done = control(&mut state, 8, Command::Commit { transaction: 1 }).unwrap();
    assert_eq!(control::decode_reply(done.reply), Some(63));
    assert!(done.redraw);
    state
}
fn header(state: &State, slot: Slot, frame: u64) -> Header {
    let w = state.scene.slots[slot.index()].unwrap().window;
    let r = w.registration;
    Header {
        producer: r.producer,
        instance: r.instance,
        process: r.process,
        thread: r.thread,
        incarnation: r.incarnation,
        surface_object: r.surface_object,
        surface_generation: r.surface_generation,
        frame,
        view_revision: 1,
        model_revision: state.scene.model_revision,
        width: w.bounds.width,
        height: w.bounds.height,
        stride_bytes: w.bounds.width * 4,
        payload_bytes: w.bounds.width * w.bounds.height * 4,
        mapping_epoch: r.mapping_epoch,
        protected_scope_nonce: 0,
    }
}
struct Sink {
    width: usize,
    height: usize,
    pixels: Vec<Color>,
    writes: usize,
    fail_at: usize,
}
impl Sink {
    fn new(scale: usize) -> Self {
        let width = 640 * scale;
        let height = 480 * scale;
        Self {
            width,
            height,
            pixels: vec![SENTINEL; width * height + 2],
            writes: 0,
            fail_at: usize::MAX,
        }
    }
    fn at(&self, x: usize, y: usize) -> Color {
        self.pixels[1 + y * self.width + x]
    }
    fn guards(&self) {
        assert_eq!(self.pixels[0], SENTINEL);
        assert_eq!(*self.pixels.last().unwrap(), SENTINEL);
    }
    fn protected_is(&self, scale: usize, color: Color) {
        for y in 0..80 * scale {
            for x in 0..640 * scale {
                assert_eq!(self.at(x, y), color);
            }
        }
    }
}
impl Pixels for Sink {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), ev_graphics::Error> {
        assert!(x < self.width && y < self.height);
        if self.writes == self.fail_at {
            return Err(ev_graphics::Error::Bounds);
        }
        self.writes += 1;
        self.pixels[1 + y * self.width + x] = color;
        Ok(())
    }
}
struct Source {
    header: Header,
    samples: Cell<usize>,
    checks: usize,
    fail_check: usize,
    color: Color,
}
impl Source {
    fn new(header: Header, color: Color) -> Self {
        Self {
            header,
            samples: Cell::new(0),
            checks: 0,
            fail_check: usize::MAX,
            color,
        }
    }
}
impl FramePixels for Source {
    fn raster(&self) -> Raster {
        Raster {
            width: self.header.width,
            height: self.header.height,
            stride_pixels: self.header.stride_bytes / 4,
            extent_bytes: u64::from(self.header.payload_bytes),
        }
    }
    fn checkpoint(&mut self) -> Result<(), ComposeError> {
        self.checks += 1;
        if self.checks == self.fail_check {
            return Err(ComposeError::Stale);
        }
        Ok(())
    }
    fn sample(&self, x: u32, y: u32) -> Result<Color, ComposeError> {
        assert!(x < self.header.width && y < self.header.height);
        self.samples.set(self.samples.get() + 1);
        Ok(self.color)
    }
}

#[test]
fn actual_receiver_and_origin_resolve_before_source_access() {
    let state = scene();
    let auth = authority();
    assert!(auth.capture(106, 2, root()).is_err());
    assert!(auth.capture(109, 3, root()).is_err());
    assert_eq!(
        state.resolve(owner(Slot::EditorOne), 2),
        Ok(Slot::EditorOne)
    );
    for foreign in [
        Origin {
            process: 999,
            ..owner(Slot::Files)
        },
        Origin {
            thread: 999,
            ..owner(Slot::Files)
        },
        Origin {
            incarnation: 999,
            ..owner(Slot::Files)
        },
        Origin {
            status: 1,
            ..owner(Slot::Files)
        },
        Origin {
            serial: 3,
            ..owner(Slot::Files)
        },
    ] {
        assert!(state.resolve(foreign, 2).is_err());
    }
    let forged = header(&state, Slot::ProtectedRoot, 1);
    assert!(
        state
            .prepare(owner(Slot::Files), 2, 1, Slot::Files, forged)
            .is_err()
    );
    assert!(
        state
            .prepare(owner(Slot::Files), 2, 1, Slot::ProtectedRoot, forged)
            .is_err()
    );
}
#[test]
fn full_frame_view_model_mapping_and_extent_fences() {
    let mut state = scene();
    let slot = Slot::EditorOne;
    let origin = owner(slot);
    let good = header(&state, slot, 0x1_0000_0007);
    for bad in [
        Header {
            model_revision: 2,
            ..good
        },
        Header {
            mapping_epoch: 2,
            ..good
        },
        Header {
            surface_generation: 999,
            ..good
        },
        Header {
            surface_object: Slot::EditorTwo.source().selector(),
            ..good
        },
        Header { width: 319, ..good },
        Header {
            stride_bytes: 1279,
            ..good
        },
        Header {
            payload_bytes: u32::MAX,
            ..good
        },
        Header {
            view_revision: 0,
            ..good
        },
    ] {
        assert!(state.prepare(origin, 2, good.frame, slot, bad).is_err());
    }
    assert!(state.prepare(origin, 2, 7, slot, good).is_err());
    let plan = state.prepare(origin, 2, good.frame, slot, good).unwrap();
    assert_eq!(
        state.commit_present(
            plan,
            Origin {
                call_epoch: 2,
                ..origin
            }
        ),
        Err(Error::Stale)
    );
    assert_eq!(state.scene.ready_mask(), 0);
    assert_eq!(state.commit_present(plan, origin), Ok(good.frame));
    assert_eq!(state.scene.slots[1].unwrap().last_frame, good.frame);
    assert!(state.prepare(origin, 2, good.frame, slot, good).is_err());
}
#[test]
fn current_owner_only_copy_respects_higher_geometry_and_protected_plane() {
    let mut state = scene();
    // Overlap two independently registered owners; no other owner's bytes are
    // available to this copy, only the Root-authorized occluding geometry.
    let mut higher = window(Slot::EditorOne);
    higher.registration.sequence = 2;
    higher.bounds = control::Bounds {
        x: 100,
        y: 111,
        width: 100,
        height: 100,
    };
    control(
        &mut state,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 2,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
        },
    )
    .unwrap();
    control(
        &mut state,
        10,
        Command::Register {
            transaction: 2,
            window: higher,
        },
    )
    .unwrap();
    control(&mut state, 11, Command::Commit { transaction: 2 }).unwrap();
    let mut sink = Sink::new(1);
    state.redraw(&mut sink).unwrap();
    sink.protected_is(1, SENTINEL);
    let h = header(&state, Slot::Files, 1);
    let plan = state
        .prepare(owner(Slot::Files), 2, 1, Slot::Files, h)
        .unwrap();
    let mut source = Source::new(h, Color(0xff0000));
    state.paint(plan, &mut source, &mut sink).unwrap();
    assert_eq!(sink.at(10, 100), source.color);
    assert_ne!(sink.at(150, 150), source.color);
    assert_ne!(sink.at(99, 110), source.color);
    assert!(source.samples.get() > 0 && source.samples.get() < 320 * 180);
    sink.protected_is(1, SENTINEL);
    sink.guards();
    let h = header(&state, Slot::ProtectedRoot, 1);
    let plan = state.prepare(root(), 2, 1, Slot::ProtectedRoot, h).unwrap();
    let mut source = Source::new(h, Color(0x00ff00));
    state.paint(plan, &mut source, &mut sink).unwrap();
    sink.protected_is(1, source.color);
    assert_eq!(sink.at(10, 100), Color(0xff0000));
    assert_eq!(source.samples.get(), 640 * 80);
    sink.guards();
}
#[test]
fn commit_neutralizes_exposed_pixels_and_requires_fresh_owner_frames() {
    let mut state = scene();
    let mut sink = Sink::new(1);
    let h = header(&state, Slot::Files, 1);
    let plan = state
        .prepare(owner(Slot::Files), 2, 1, Slot::Files, h)
        .unwrap();
    let mut source = Source::new(h, Color(0xff0000));
    state.paint(plan, &mut source, &mut sink).unwrap();
    state.commit_present(plan, owner(Slot::Files)).unwrap();
    control(
        &mut state,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 2,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: true,
                thick_focus: true,
            },
        },
    )
    .unwrap();
    assert_eq!(
        state.resolve(owner(Slot::Files), 2),
        Err(Error::Transaction)
    );
    assert_eq!(
        state.paint(plan, &mut source, &mut sink),
        Err(ComposeError::Stale)
    );
    let done = control(&mut state, 10, Command::Commit { transaction: 2 }).unwrap();
    assert_eq!(control::decode_reply(done.reply), Some(63));
    assert_eq!(state.scene.ready_mask(), 0);
    state.redraw(&mut sink).unwrap();
    assert_ne!(sink.at(10, 100), source.color);
    sink.protected_is(1, SENTINEL);
    sink.guards();
    assert!(
        state
            .prepare(
                owner(Slot::Files),
                2,
                2,
                Slot::Files,
                Header { frame: 2, ..h }
            )
            .is_err()
    );
    assert!(state.commit_present(plan, owner(Slot::Files)).is_err());
}
#[test]
fn hidden_frames_make_no_pixel_reads_and_interruption_never_advances_frame() {
    let mut state = scene();
    let mut hidden = window(Slot::Files);
    hidden.visible = false;
    hidden.registration.sequence = 2;
    control(
        &mut state,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 2,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
        },
    )
    .unwrap();
    control(
        &mut state,
        10,
        Command::Register {
            transaction: 2,
            window: hidden,
        },
    )
    .unwrap();
    control(&mut state, 11, Command::Commit { transaction: 2 }).unwrap();
    let h = header(&state, Slot::Files, 1);
    let p = state
        .prepare(owner(Slot::Files), 2, 1, Slot::Files, h)
        .unwrap();
    let mut s = Source::new(h, Color(7));
    let mut sink = Sink::new(1);
    state.paint(p, &mut s, &mut sink).unwrap();
    assert_eq!(s.samples.get(), 0);
    assert_eq!(sink.writes, 0);
    state.commit_present(p, owner(Slot::Files)).unwrap();
    assert_eq!(state.scene.ready_mask(), 0);
    let h = header(&state, Slot::EditorOne, 1);
    let p = state
        .prepare(owner(Slot::EditorOne), 2, 1, Slot::EditorOne, h)
        .unwrap();
    let mut s = Source::new(h, Color(8));
    s.fail_check = 3;
    assert!(state.paint(p, &mut s, &mut sink).is_err());
    assert_eq!(state.scene.slots[1].unwrap().last_frame, 0);
    assert!(s.samples.get() > 0);
    sink.protected_is(1, SENTINEL);
    sink.guards();
    let mut s = Source::new(h, Color(8));
    sink.fail_at = sink.writes + 10;
    assert!(state.paint(p, &mut s, &mut sink).is_err());
    assert_eq!(state.scene.slots[1].unwrap().last_frame, 0);
}
#[test]
fn interrupted_repaint_invalidates_old_accepted_view_before_partial_scanout() {
    let mut state = scene();
    let slot = Slot::EditorOne;
    let initial = control(&mut state, 9, Command::Inspect { slot, field: 6 })
        .unwrap()
        .reply;
    let h = header(&state, slot, 1);
    let plan = state.prepare(owner(slot), 2, 1, slot, h).unwrap();
    let mut sink = Sink::new(1);
    state
        .paint(plan, &mut Source::new(h, Color(7)), &mut sink)
        .unwrap();
    let copying = control(&mut state, 10, Command::Inspect { slot, field: 6 })
        .unwrap()
        .reply;
    assert!(copying > initial);
    assert_eq!(state.scene.ready_mask(), 0);
    state.commit_present(plan, owner(slot)).unwrap();
    let completed = control(&mut state, 11, Command::Inspect { slot, field: 6 })
        .unwrap()
        .reply;
    assert!(completed > copying);
    assert_eq!(state.scene.ready_mask(), 1 << slot.index());
    let other = Slot::Files;
    let other_header = header(&state, other, 1);
    let other_plan = state
        .prepare(owner(other), 2, 1, other, other_header)
        .unwrap();
    state
        .paint(
            other_plan,
            &mut Source::new(other_header, Color(6)),
            &mut sink,
        )
        .unwrap();
    state.commit_present(other_plan, owner(other)).unwrap();
    assert_eq!(
        control(&mut state, 12, Command::Inspect { slot, field: 6 })
            .unwrap()
            .reply,
        completed
    );
    let h = Header {
        frame: 2,
        view_revision: h.view_revision + 1,
        ..h
    };
    let plan = state.prepare(owner(slot), 2, 2, slot, h).unwrap();
    let mut source = Source::new(h, Color(8));
    source.fail_check = 3;
    assert!(state.paint(plan, &mut source, &mut sink).is_err());
    let interrupted = control(&mut state, 13, Command::Inspect { slot, field: 6 })
        .unwrap()
        .reply;
    assert!(interrupted > completed);
    assert!(source.samples.get() > 0);
    assert_eq!(state.scene.ready_mask(), 1 << other.index());
    assert_eq!(state.scene.slots[slot.index()].unwrap().last_frame, 1);
    assert_eq!(
        state.scene.slots[slot.index()].unwrap().last_view,
        h.view_revision - 1
    );
    sink.protected_is(1, SENTINEL);
    sink.guards();
    state.presentation_epoch = u64::MAX - 1;
    let mut source = Source::new(h, Color(9));
    assert_eq!(
        state.paint(plan, &mut source, &mut sink),
        Err(ComposeError::Stale)
    );
    assert_eq!(source.samples.get(), 0);
}
#[test]
fn replacement_has_distinct_binding_and_old_provider_cannot_present() {
    let mut state = scene();
    let old = header(&state, Slot::EditorTwo, 1);
    let old_plan = state
        .prepare(owner(Slot::EditorTwo), 2, 1, Slot::EditorTwo, old)
        .unwrap();
    let mut new = window(Slot::EditorTwo);
    new.registration.sequence = 2;
    new.registration.process = 200;
    new.registration.thread = 201;
    new.registration.incarnation = 202;
    new.registration.mapping_epoch = 2;
    new.registration.surface_generation = 200;
    control(
        &mut state,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 2,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
        },
    )
    .unwrap();
    control(
        &mut state,
        10,
        Command::Register {
            transaction: 2,
            window: new,
        },
    )
    .unwrap();
    control(&mut state, 11, Command::Commit { transaction: 2 }).unwrap();
    assert_eq!(
        state.resolve(owner(Slot::EditorTwo), 2),
        Err(Error::Unknown)
    );
    assert!(
        state
            .commit_present(old_plan, owner(Slot::EditorTwo))
            .is_err()
    );
    let origin = Origin {
        process: 200,
        thread: 201,
        incarnation: 202,
        ..owner(Slot::EditorTwo)
    };
    let h = header(&state, Slot::EditorTwo, 1);
    assert!(state.prepare(origin, 2, 1, Slot::EditorTwo, h).is_ok());
}
#[test]
fn transactions_reject_wrong_root_protected_owner_duplicate_owner_and_z() {
    let mut state = scene();
    control(
        &mut state,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 2,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
        },
    )
    .unwrap();
    let mut fake = window(Slot::ProtectedRoot);
    fake.registration.sequence = 2;
    fake.registration.process = 777;
    fake.registration.surface_generation = 777;
    assert_eq!(
        control(
            &mut state,
            10,
            Command::Register {
                transaction: 2,
                window: fake
            }
        ),
        Err(Error::Identity)
    );
    let other = Origin {
        process: 99,
        ..root()
    };
    let capture = authority().capture(109, 2, other).unwrap();
    assert_eq!(
        state.control(
            capture,
            Envelope {
                request: 10,
                command: Command::Commit { transaction: 2 }
            }
        ),
        Err(Error::Transaction)
    );
    let mut duplicate = window(Slot::EditorOne);
    duplicate.registration.sequence = 2;
    duplicate.registration.process = 10;
    duplicate.registration.surface_generation = 10;
    control(
        &mut state,
        10,
        Command::Register {
            transaction: 2,
            window: duplicate,
        },
    )
    .unwrap();
    assert_eq!(
        control(&mut state, 11, Command::Commit { transaction: 2 }),
        Err(Error::Duplicate)
    );
    control(&mut state, 11, Command::Abort { transaction: 2 }).unwrap();
    control(
        &mut state,
        12,
        Command::Begin {
            transaction: 3,
            model_revision: 2,
            preferences: control::Preferences {
                scale: 1,
                high_contrast: false,
                thick_focus: false,
            },
        },
    )
    .unwrap();
    let mut duplicate = window(Slot::EditorOne);
    duplicate.registration.sequence = 2;
    duplicate.z = 0;
    control(
        &mut state,
        13,
        Command::Register {
            transaction: 3,
            window: duplicate,
        },
    )
    .unwrap();
    assert_eq!(
        control(&mut state, 14, Command::Commit { transaction: 3 }),
        Err(Error::Duplicate)
    );
}
#[test]
fn exact_semantic_view_and_physical_scale_are_fenced() {
    let mut state = scene();
    let mut exact = window(Slot::Files);
    exact.registration.sequence = 2;
    exact.strict_view = true;
    exact.view_revision = 7;
    control(
        &mut state,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 0x1_0000_0001,
            preferences: control::Preferences {
                scale: 2,
                high_contrast: true,
                thick_focus: true,
            },
        },
    )
    .unwrap();
    control(
        &mut state,
        10,
        Command::Register {
            transaction: 2,
            window: exact,
        },
    )
    .unwrap();
    control(&mut state, 11, Command::Commit { transaction: 2 }).unwrap();
    let h = header(&state, Slot::Files, 1);
    assert!(
        state
            .prepare(owner(Slot::Files), 2, 1, Slot::Files, h)
            .is_err()
    );
    let h = Header {
        view_revision: 7,
        ..h
    };
    let p = state
        .prepare(owner(Slot::Files), 2, 1, Slot::Files, h)
        .unwrap();
    let mut s = Source::new(h, Color(9));
    let mut wrong = Sink::new(1);
    assert!(state.paint(p, &mut s, &mut wrong).is_err());
    assert_eq!(s.samples.get(), 0);
    let mut sink = Sink::new(2);
    state.redraw(&mut sink).unwrap();
    state.paint(p, &mut s, &mut sink).unwrap();
    assert_eq!(sink.at(20, 200), s.color);
    sink.protected_is(2, SENTINEL);
    sink.guards();
    assert!(
        control(
            &mut state,
            12,
            Command::Begin {
                transaction: 3,
                model_revision: 0x1_0000_0002,
                preferences: control::Preferences {
                    scale: 3,
                    high_contrast: false,
                    thick_focus: false
                }
            }
        )
        .is_err()
    );
}

#[test]
fn cursor_and_maxscale_require_root_control_and_do_not_change_ordinary_bindings() {
    let mut state = scene();
    let before = state.scene;
    assert!(authority().capture(106, 2, owner(Slot::Files)).is_err());
    let effect = control(
        &mut state,
        9,
        Command::Cursor {
            x: 639,
            y: 479,
            visible: true,
        },
    )
    .unwrap();
    assert!(effect.cursor);
    assert!(!effect.redraw);
    assert_eq!(state.cursor(), Some((639, 479)));
    assert_eq!(state.scene, before);
    assert_eq!(
        control(
            &mut state,
            10,
            Command::Inspect {
                slot: Slot::ProtectedRoot,
                field: 5
            }
        )
        .unwrap()
        .reply,
        2
    );
    assert!(
        control(
            &mut state,
            11,
            Command::Cursor {
                x: 640,
                y: 479,
                visible: true
            }
        )
        .is_err()
    );
    assert_eq!(state.cursor(), Some((639, 479)));
    control(
        &mut state,
        11,
        Command::Cursor {
            x: 0,
            y: 0,
            visible: false,
        },
    )
    .unwrap();
    assert_eq!(state.cursor(), None);
}

#[path = "tests/credit_checkpoint.rs"]
mod credit_checkpoint;
