use super::*;

struct CheckedSource {
    inner: Source,
    origin: Origin,
    clocked: bool,
    now: u64,
    expire_after_row_query: bool,
    expire_before: usize,
}
impl FramePixels for CheckedSource {
    fn raster(&self) -> Raster {
        self.inner.raster()
    }
    fn checkpoint(&mut self) -> Result<(), ComposeError> {
        self.inner.checks += 1;
        if self.inner.checks == self.expire_before {
            self.now = self.origin.deadline;
        }
        let reply = CreditStatus {
            status: 0,
            value: if self.now >= self.origin.deadline {
                2
            } else {
                0
            },
            capability: 0,
            serial: 0,
        };
        let live = if self.clocked {
            self.origin.live_checkpoint(reply, self.now)
        } else {
            self.origin.kernel_checkpoint(reply)
        };
        // Model expiry immediately after the second query (first pixel row),
        // while the accepted immutable producer credit is still retained.
        if self.expire_after_row_query && self.inner.checks == 2 {
            self.now = self.origin.deadline;
        }
        if live {
            Ok(())
        } else {
            Err(ComposeError::Stale)
        }
    }
    fn sample(&self, x: u32, y: u32) -> Result<Color, ComposeError> {
        self.inner.samples.set(self.inner.samples.get() + 1);
        Ok(Color(
            ((x * 17 + y * 31) & 255) << 16 | ((x * 7 + y * 13) & 255) << 8 | ((x + y * 3) & 255),
        ))
    }
}
fn configured(variant: usize, scale: u8) -> State {
    let mut s = scene();
    control(
        &mut s,
        9,
        Command::Begin {
            transaction: 2,
            model_revision: 2,
            preferences: control::Preferences {
                scale,
                high_contrast: variant == 1,
                thick_focus: variant == 1,
            },
        },
    )
    .unwrap();
    for slot in control::SLOTS {
        let mut w = window(slot);
        w.registration.sequence = 2;
        if slot == Slot::Files && variant == 1 {
            w.focused = false;
        }
        if slot == Slot::EditorOne && variant == 1 {
            w.bounds = control::Bounds {
                x: 110,
                y: 101,
                width: 120,
                height: 120,
            };
            w.focused = true;
        }
        if slot == Slot::Files && variant == 2 {
            w.visible = false;
        }
        if slot == Slot::Files && variant == 3 {
            w.bounds = control::Bounds {
                x: 25,
                y: 105,
                width: 250,
                height: 160,
            };
        }
        control(
            &mut s,
            10 + slot.index() as u64,
            Command::Register {
                transaction: 2,
                window: w,
            },
        )
        .unwrap();
    }
    control(&mut s, 20, Command::Commit { transaction: 2 }).unwrap();
    s
}
#[test]
fn same_live_credit_pixels_across_occlusion_protected_shell_hide_move_resize_and_scale() {
    for (variant, scale) in [(0, 1), (1, 1), (1, 2), (2, 1), (3, 1), (3, 2)] {
        for slot in control::SLOTS {
            let mut old = configured(variant, scale);
            let mut new = configured(variant, scale);
            let mut a = Sink::new(scale as usize);
            let mut b = Sink::new(scale as usize);
            old.redraw(&mut a).unwrap();
            new.redraw(&mut b).unwrap();
            // Protected sentinel/content and chrome remain identical outside
            // this producer, including overlaps and negative Root-plane clip.
            let h = header(&old, slot, 1);
            let origin = owner(slot);
            let old_plan = old.prepare(origin, origin.serial, 1, slot, h).unwrap();
            let new_plan = new.prepare(origin, origin.serial, 1, slot, h).unwrap();
            let source = |clocked| CheckedSource {
                inner: Source::new(h, Color(0)),
                origin,
                clocked,
                now: 1,
                expire_after_row_query: false,
                expire_before: usize::MAX,
            };
            let mut x = source(true);
            let mut y = source(false);
            old.paint(old_plan, &mut x, &mut a).unwrap();
            new.paint(new_plan, &mut y, &mut b).unwrap();
            assert_eq!(
                a.pixels, b.pixels,
                "variant{variant}/scale{scale}/slot{slot:?}"
            );
            assert_eq!(a.writes, b.writes);
            assert_eq!(x.inner.samples.get(), y.inner.samples.get());
            assert_eq!(x.inner.checks, y.inner.checks);
            assert_eq!(old.scene.ready_mask(), new.scene.ready_mask());
            assert_eq!(
                old.commit_present(old_plan, origin),
                new.commit_present(new_plan, origin)
            );
            a.guards();
            b.guards();
        }
    }
}
#[test]
fn expiry_after_live_row_query_copies_at_most_one_row_and_never_restores_ready() {
    let mut state = scene();
    let slot = Slot::Files;
    let h = header(&state, slot, 1);
    let origin = owner(slot);
    let p = state.prepare(origin, origin.serial, 1, slot, h).unwrap();
    let mut sink = Sink::new(1);
    let mut source = CheckedSource {
        inner: Source::new(h, Color(0)),
        origin,
        clocked: false,
        now: origin.deadline - 1,
        expire_after_row_query: true,
        expire_before: usize::MAX,
    };
    assert_eq!(
        state.paint(p, &mut source, &mut sink),
        Err(ComposeError::Stale)
    );
    assert!(source.inner.samples.get() > 0 && source.inner.samples.get() <= h.width as usize);
    assert_eq!(source.inner.checks, 3);
    assert_eq!(state.scene.ready_mask(), 0);
    assert_eq!(state.scene.slots[slot.index()].unwrap().last_frame, 0);
    sink.protected_is(1, SENTINEL);
    sink.guards();
}
#[test]
fn already_expired_authenticated_status_reads_no_pixels_or_protected_bytes() {
    let mut state = scene();
    let slot = Slot::ProtectedRoot;
    let h = header(&state, slot, 1);
    let origin = owner(slot);
    let p = state.prepare(origin, origin.serial, 1, slot, h).unwrap();
    let mut sink = Sink::new(1);
    let mut source = CheckedSource {
        inner: Source::new(h, Color(0)),
        origin,
        clocked: false,
        now: origin.deadline,
        expire_after_row_query: false,
        expire_before: usize::MAX,
    };
    assert_eq!(
        state.paint(p, &mut source, &mut sink),
        Err(ComposeError::Stale)
    );
    assert_eq!(source.inner.samples.get(), 0);
    assert_eq!(sink.writes, 0);
    assert_eq!(state.scene.ready_mask(), 0);
    sink.guards();
}

#[test]
fn expiry_at_every_existing_checkpoint_stops_without_publication_or_credit_replacement() {
    let slot = Slot::Files;
    for cut_check in 1..=182 {
        let mut state = scene();
        let h = header(&state, slot, 1);
        let origin = owner(slot);
        let plan = state.prepare(origin, origin.serial, 1, slot, h).unwrap();
        let mut sink = Sink::new(1);
        let mut source = CheckedSource {
            inner: Source::new(h, Color(0)),
            origin,
            clocked: false,
            now: 1,
            expire_after_row_query: false,
            expire_before: cut_check,
        };
        assert_eq!(
            state.paint(plan, &mut source, &mut sink),
            Err(ComposeError::Stale)
        );
        assert_eq!(source.inner.checks, cut_check);
        assert_eq!(source.origin, origin);
        assert!(source.inner.samples.get() <= h.width as usize * cut_check.saturating_sub(2));
        assert_eq!(state.scene.ready_mask(), 0);
        assert_eq!(state.scene.slots[slot.index()].unwrap().last_frame, 0);
        sink.protected_is(1, SENTINEL);
        sink.guards();
    }
}
