use super::*;
use ev_userspace_contract::root_v5::{assistive as at, display_control::Slot};

fn header(page: u8, nonce: u32) -> Header {
    Header {
        nonce,
        page,
        pages: 1,
        model: 0x1_0000_0001,
        view: 0x2_0000_0002,
        frame: 0x3_0000_0003,
        mapping_epoch: 0x4_0000_0004,
        width: 320,
        height: 180,
        keyboard: 0,
        modal: 0,
    }
}
fn model() -> Model {
    let mut m = Model::new();
    let mut words = [0u64; 128];
    words[0] = 7;
    words[1] = 1;
    words[2] = 41;
    words[3] = 42;
    words[5] = u64::MAX;
    words[6] = u64::MAX;
    words[7] = 0xfedc_ba98_7654_3210;
    words[8] = 100;
    words[74] = 12;
    words[75] = 1;
    words[76] = 2;
    words[120] = 1;
    words[121] = 1;
    words[127] = 7;
    for (i, word) in words.into_iter().enumerate() {
        if !crate::field::required(i as u8) && i != 127 {
            continue;
        }
        for high in [false, true] {
            m.put(i as u8, high, (word >> (if high { 32 } else { 0 })) as u32)
                .unwrap();
        }
    }
    m
}
fn reader(scopes: u8, protected: bool) -> Consumer {
    let mut c = Consumer::new();
    c.receive(
        at::Context {
            mode: at::Mode::Receiving,
            source: if protected {
                Slot::ProtectedRoot
            } else {
                Slot::EditorOne
            },
            scopes,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    c.receive(at::commit(8).unwrap()).unwrap();
    c.receive(
        a1::Request::Snapshot { page: 0, nonce: 8 }
            .frame()
            .unwrap()
            .encode(),
    )
    .unwrap();
    let mut s = a1::Snapshot::EMPTY;
    let mut h = header(0, 8);
    let mut root = node(
        1,
        Role::Window,
        "Secret native filename",
        rect(0, 0, 320, 180),
    )
    .unwrap();
    root.parent = 0;
    if protected {
        h.modal = 16;
    }
    let secret = node(
        16,
        if protected { Role::Dialog } else { Role::Label },
        "PRIVATE_DOCUMENT_SECRET",
        rect(0, 0, 50, 20),
    )
    .unwrap();
    s.replace(h, &[root, secret]).unwrap();
    for i in 0..s.frames() {
        c.receive(s.frame(i).unwrap().encode()).unwrap();
    }
    c
}
fn tree(page: u8, m: &Model, c: &Consumer, focus: Option<u16>) -> a1::Snapshot {
    let mut p = a1::Publisher::new();
    publish(&mut p, header(page, 9), m, c, focus).unwrap();
    let mut rx = a1::Receiver::new();
    rx.request(page, 9).unwrap();
    let mut completed = false;
    while let Some(f) = p.next() {
        completed = rx.push(f).unwrap() == a1::Progress::Complete;
        p.sent(f).unwrap();
    }
    assert!(completed);
    let mut out = a1::Snapshot::EMPTY;
    rx.candidate(&mut out).unwrap();
    out
}
#[test]
fn reader_action_scope_requires_actual_complete_self_commit_and_same_accepted_frame() {
    let model = model();
    let consumer = reader(1, false);
    let mut h = header(1, 9);
    h.view = 8; // actual accepted Inspector consumer nonce, not source view
    let mut session = Session::new();
    session
        .request(
            Request::Snapshot { page: 1, nonce: 9 },
            h,
            &model,
            &consumer,
            Some(201),
            true,
        )
        .unwrap();
    while let Some(bytes) = session.next() {
        assert!(
            session
                .ordinary_scope(h, &consumer, Some(201), true)
                .is_none()
        );
        session.sent(bytes).unwrap();
    }
    let scope = session
        .ordinary_scope(h, &consumer, Some(201), true)
        .unwrap();
    assert_eq!(
        (scope.header.nonce, scope.header.view, scope.control),
        (9, 8, 201)
    );
    assert!(
        session
            .ordinary_scope(h, &consumer, Some(202), true)
            .is_none()
    );
    assert!(
        session
            .ordinary_scope(h, &consumer, Some(201), false)
            .is_none()
    );
    let mut newer = h;
    newer.frame += 1;
    assert!(
        session
            .ordinary_scope(newer, &consumer, Some(201), true)
            .is_none()
    );
    session
        .request(
            Request::Snapshot { page: 1, nonce: 10 },
            h,
            &model,
            &consumer,
            Some(201),
            true,
        )
        .unwrap();
    assert!(
        session
            .ordinary_scope(h, &consumer, Some(201), true)
            .is_none()
    );
}
#[test]
fn disjoint_self_codec_rejects_external_frames_reserved_pages_and_nonces() {
    for request in [
        Request::Snapshot { page: 4, nonce: 9 },
        Request::Abort { nonce: 9 },
    ] {
        assert_eq!(Request::decode(request.encode().unwrap()), Ok(request));
    }
    assert!(Request::Snapshot { page: 5, nonce: 9 }.encode().is_err());
    for nonce in [0, u32::MAX] {
        assert!(Request::Abort { nonce }.encode().is_err());
    }
    let external = a1::Request::Snapshot { page: 0, nonce: 9 }
        .frame()
        .unwrap()
        .encode();
    assert!(Request::decode(external).is_err());
    assert!(decode_reply(external).is_err());
    let mut bad = Request::Abort { nonce: 9 }.encode().unwrap();
    bad[3] = 1;
    assert!(Request::decode(bad).is_err());
    let frame = Frame {
        field: a1::COMMIT,
        word: 0xfedc_ba98,
    };
    assert_eq!(decode_reply(reply(frame)), Ok(frame));
    assert!(Frame::decode(&reply(frame)).is_err());
}
#[test]
fn all_own_control_pages_keep_exact_tuple_geometry_and_sixteen_node_bound() {
    let m = model();
    let c = Consumer::new();
    for page in 0..4 {
        let s = tree(page, &m, &c, None);
        assert!(s.nodes().len() <= 16);
        let h = s.header();
        let expected = header(page, 9);
        assert_eq!(
            (h.model, h.view, h.frame, h.mapping_epoch),
            (
                expected.model,
                expected.view,
                expected.frame,
                expected.mapping_epoch
            )
        );
        assert_eq!(h.pages, 4);
        for n in s.nodes() {
            assert!(n.bounds.x + n.bounds.width <= 320 && n.bounds.y + n.bounds.height <= 180);
        }
    }
    for c in [reader(1, false), reader(15, true)] {
        for page in 0..5 {
            let s = tree(page, &m, &c, None);
            assert!(s.nodes().len() <= 16);
            assert_eq!(s.header().pages, 5);
        }
    }
}
#[test]
fn stats_use_only_published_full64_sample_and_exact_disabled_actions() {
    let mut m = model();
    let c = Consumer::new();
    m.put(0, false, 8).unwrap();
    m.put(0, true, 0).unwrap();
    m.put(5, false, 1).unwrap();
    let s = tree(2, &m, &c, None);
    assert!(
        s.nodes()
            .iter()
            .any(|n| n.label.as_str() == "CPU used: 18446744073709551615")
    );
    assert!(
        s.nodes()
            .iter()
            .any(|n| n.label.as_str() == "Frames used: 18364758544493064720")
    );
    let controls = tree(1, &m, &c, Some(16));
    assert_eq!(controls.header().keyboard, 16);
    assert_eq!(controls.nodes().len(), 15);
    m.select(1);
    let disabled = tree(1, &m, &c, None);
    for id in 19..=22 {
        let n = disabled.nodes().iter().find(|n| n.local == id).unwrap();
        assert_eq!((n.flags, n.actions), (1, 0));
    }
}
#[test]
fn no_self_projection_reexports_nested_provider_labels_or_text_ranges() {
    let m = model();
    let c = reader(15, true);
    for page in 0..5 {
        let s = tree(page, &m, &c, None);
        for n in s.nodes() {
            assert!(!n.label.as_str().contains("PRIVATE_DOCUMENT_SECRET"));
            assert!(!n.label.as_str().contains("Secret native filename"));
            assert!(!matches!(n.value, Value::TextRange { .. }));
        }
    }
}
#[test]
fn scope_bits_disable_real_tools_and_protected_confirm_has_no_ordinary_action() {
    let m = model();
    let read = reader(1, true);
    let actions = tree(1, &m, &read, None);
    for id in [204, 205, 208] {
        let n = actions.nodes().iter().find(|n| n.local == id).unwrap();
        assert_eq!((n.flags, n.actions), (1, 0));
    }
    let full = reader(15, true);
    let controls = tree(2, &m, &full, None);
    let confirm = controls.nodes().iter().find(|n| n.local == 213).unwrap();
    assert_eq!((confirm.flags, confirm.actions), (2, 0));
    assert_eq!(ordinary_control(&m, &full, 213), None);
    assert!(full.protected_confirm(213)); // Existing dedicated physical route stays separate.
}
#[test]
fn local_focus_reaches_every_visible_enabled_control_but_never_confirm() {
    let m = model();
    for c in [Consumer::new(), reader(15, true)] {
        let mut current = None;
        let mut seen = std::vec::Vec::new();
        for _ in 0..40 {
            let next = next_control(&m, &c, current, true, 320, 180).unwrap();
            if seen.contains(&next) {
                break;
            }
            assert_ne!(next, 213);
            assert!(ordinary_control(&m, &c, next).is_some());
            seen.push(next);
            current = Some(next);
        }
        assert_eq!(
            next_control(&m, &c, Some(seen[0]), false, 320, 180),
            seen.last().copied()
        );
        for id in if c.active() { 201..219 } else { 16..30 } {
            if ordinary_control(&m, &c, id).is_some() {
                assert!(seen.contains(&id));
            }
        }
    }
}
#[test]
fn unaccepted_present_refuses_and_immutable_stream_waits_for_real_send_or_abort() {
    let m = model();
    let c = Consumer::new();
    let mut session = Session::new();
    let q = Request::Snapshot { page: 1, nonce: 9 };
    session
        .request(q, header(0, 1), &m, &c, None, false)
        .unwrap();
    let refusal = session.next().unwrap();
    assert_eq!(
        decode_reply(refusal).unwrap(),
        Frame {
            field: 0x7f01,
            word: 9
        }
    );
    assert_eq!(session.next(), Some(refusal));
    session.sent(refusal).unwrap();
    session
        .request(
            Request::Snapshot { page: 1, nonce: 10 },
            header(0, 1),
            &m,
            &c,
            None,
            true,
        )
        .unwrap();
    let first = session.next().unwrap();
    assert_eq!(decode_reply(first).unwrap().word, 10);
    assert!(
        session
            .request(
                Request::Snapshot { page: 0, nonce: 11 },
                header(0, 1),
                &m,
                &c,
                None,
                true
            )
            .is_err()
    );
    let mut wrong = first;
    wrong[4] ^= 1;
    assert!(session.sent(wrong).is_err());
    assert_eq!(session.next(), Some(first));
    assert!(
        session
            .request(
                Request::Abort { nonce: 11 },
                header(0, 1),
                &m,
                &c,
                None,
                false
            )
            .is_err()
    );
    session
        .request(
            Request::Abort { nonce: 10 },
            header(0, 1),
            &m,
            &c,
            None,
            false,
        )
        .unwrap();
    let ack = session.next().unwrap();
    assert_eq!(
        decode_reply(ack).unwrap(),
        Frame {
            field: a1::ABORT_ACK,
            word: 10
        }
    );
    assert_eq!(session.next(), Some(ack));
    session.sent(ack).unwrap();
    assert!(session.next().is_none());
    assert!(
        session
            .request(
                Request::Snapshot { page: 0, nonce: 10 },
                header(0, 1),
                &m,
                &c,
                None,
                true
            )
            .is_err()
    );
}
#[test]
fn partial_external_stream_is_never_described_as_accepted_own_view() {
    let m = model();
    let mut c = Consumer::new();
    c.receive(
        at::Context {
            mode: at::Mode::Receiving,
            source: Slot::EditorOne,
            scopes: 1,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    c.receive(at::commit(8).unwrap()).unwrap();
    let mut s = Session::new();
    s.request(
        Request::Snapshot { page: 0, nonce: 9 },
        header(0, 1),
        &m,
        &c,
        None,
        true,
    )
    .unwrap();
    assert_eq!(decode_reply(s.next().unwrap()).unwrap().field, 0x7f01);
}
#[test]
fn supported_small_geometry_never_exports_hidden_or_outside_controls() {
    let m = model();
    let c = Consumer::new();
    for (width, height) in [(120, 80), (128, 80), (160, 90), (320, 180), (320, 200)] {
        for page in 0..4 {
            let mut p = a1::Publisher::new();
            let mut h = header(page, 9);
            h.width = width;
            h.height = height;
            publish(&mut p, h, &m, &c, None).unwrap();
        }
        let mut current = None;
        for _ in 0..36 {
            let Some(id) = next_control(&m, &c, current, true, width, height) else {
                break;
            };
            let b = bounds(id, false, width, height, 0).unwrap();
            assert!(b.y + b.height <= height);
            current = Some(id);
        }
    }
}

#[test]
fn local_focus_draws_real_pixels_without_crossing_viewport_or_enabling_confirm() {
    struct Memory {
        w: usize,
        h: usize,
        pixels: std::vec::Vec<u32>,
    }
    impl Pixels for Memory {
        fn dimensions(&self) -> (usize, usize) {
            (self.w, self.h)
        }
        fn write(
            &mut self,
            x: usize,
            y: usize,
            color: ev_graphics::Color,
        ) -> Result<(), GraphicsError> {
            assert!(x < self.w && y < self.h);
            self.pixels[y * self.w + x] = color.0;
            Ok(())
        }
    }
    let c = Consumer::new();
    for (w, h) in [(120, 80), (128, 80), (320, 180), (320, 200)] {
        let mut p = Memory {
            w,
            h,
            pixels: std::vec![0;w*h],
        };
        render_focus(&mut p, &c, 16).unwrap();
        assert!(p.pixels.contains(&ACCENT.0));
        assert!(p.pixels[(h - 8) * w..].contains(&INK.0));
    }
    let mut p = Memory {
        w: 321,
        h: 180,
        pixels: std::vec![0;321*180],
    };
    assert_eq!(render_focus(&mut p, &c, 16), Err(GraphicsError::Geometry));
    assert!(p.pixels.iter().all(|v| *v == 0));
    assert_eq!(
        next_control(&model(), &reader(15, true), None, true, 0, 180),
        None
    );
    assert_eq!(ordinary_control(&model(), &c, 100), Some(100));
    assert_eq!(visible_control(&model(), &c, 100, 320, 180), Some(100));
    assert_eq!(visible_control(&model(), &c, 100, 120, 80), None);
}

#[test]
fn attention_without_a_provider_enables_only_revoke_or_cancel_navigation() {
    let mut c = Consumer::new();
    c.receive(
        at::Context {
            mode: at::Mode::AttentionRequested,
            source: Slot::EditorOne,
            scopes: 1,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    c.receive(at::commit(8).unwrap()).unwrap();
    assert_eq!(next_control(&model(), &c, None, true, 320, 180), Some(212));
    assert_eq!(
        next_control(&model(), &c, Some(212), true, 320, 180),
        Some(214)
    );
    for action in 201..=218 {
        assert_eq!(c.control_enabled(action), matches!(action, 212 | 214));
    }
}
