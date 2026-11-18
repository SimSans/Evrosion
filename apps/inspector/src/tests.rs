use super::*;
use std::{vec, vec::Vec};
fn data(view: u32) -> [u64; 128] {
    let mut words = [0; 128];
    words[0] = u64::from(view);
    words[1] = 1;
    words[2] = 0x1234_5678_9abc_def0;
    words[3] = 0x2345_6789_abcd_ef01;
    words[4] = 0;
    words[5] = 0xfeed_1234_5678_9abc;
    words[6] = u64::MAX;
    words[7] = 0xfeed_cafe_1234_5678;
    words[8] = u64::MAX;
    words[9] = 1;
    words[10] = 2;
    words[11] = 1;
    words[12] = 2;
    words[74] = 12;
    words[75] = 0x1234_5678_0000_0001;
    words[76] = words[75] + 15;
    words[120] = 2;
    words[121] = 3;
    words[122] = 1;
    words[123] = 1;
    words[124] = 0b11_01_00_11;
    words[125] = 1;
    words[127] = u64::from(view);
    words
}
fn feed(model: &mut Model, words: &[u64; 128]) -> Result<bool, Error> {
    let mut published = false;
    for i in (0..128).filter(|i| field::required(*i as u8) || *i == 127) {
        let value = words[i];
        for high in [false, true] {
            published = model.put(i as u8, high, (value >> (if high { 32 } else { 0 })) as u32)?;
        }
    }
    Ok(published)
}
#[test]
fn actual_root_full64_words_publish_only_after_every_required_half_and_matching_commit() {
    let mut model = Model::new();
    let words = data(7);
    assert!(model.snapshot().is_none());
    for i in (0..127).filter(|i| field::required(*i as u8)) {
        for high in [false, true] {
            assert!(
                !model
                    .put(
                        i as u8,
                        high,
                        (words[i] >> (if high { 32 } else { 0 })) as u32
                    )
                    .unwrap()
            );
            assert!(model.snapshot().is_none());
        }
    }
    assert!(!model.put(127, false, 7).unwrap());
    assert!(model.snapshot().is_none());
    assert!(model.put(127, true, 0).unwrap());
    let s = model.snapshot().unwrap();
    assert_eq!(s.view(), 7);
    for i in (0..128).filter(|i| field::required(*i as u8)) {
        assert_eq!(s.word(i as u8), Some(words[i]));
    }
    assert_eq!(s.row(0).unwrap()[4], 0xfeed_1234_5678_9abc);
    assert_eq!(s.row(0).unwrap()[6], 0xfeed_cafe_1234_5678);
}
#[test]
fn missing_duplicate_stale_or_invalid_snapshot_never_replaces_displayed_metrics() {
    let mut model = Model::new();
    assert!(feed(&mut model, &data(1)).unwrap());
    model.put(0, false, 2).unwrap();
    model.put(0, true, 0).unwrap();
    model.put(127, false, 2).unwrap();
    assert_eq!(model.put(127, true, 0), Err(Error::Incomplete));
    assert_eq!(model.snapshot().unwrap().view(), 1);
    assert_eq!(model.put(0, false, 1), Err(Error::Order));
    model.put(0, false, 2).unwrap();
    model.put(0, true, 0).unwrap();
    model.put(1, false, 1).unwrap();
    assert_eq!(model.put(1, false, 1), Err(Error::Duplicate));
    assert_eq!(model.snapshot().unwrap().view(), 1);
    for field in [77, 119, 126, 128] {
        assert!(model.put(field, false, 0).is_err());
    }
    for mutate in [120, 121, 124, 127] {
        let mut bad = data(2);
        bad[mutate] = if mutate == 127 {
            3
        } else if mutate == 124 {
            2
        } else {
            255
        };
        assert!(feed(&mut model, &bad).is_err());
        assert_eq!(model.snapshot().unwrap().view(), 1);
    }
    assert!(feed(&mut model, &data(2)).unwrap());
    assert_eq!(model.snapshot().unwrap().view(), 2);
}
#[test]
fn throttled_paint_waits_for_real_complete_sample_without_renewing_idle_due() {
    use crate::presentation::{Presentation, STATS_IDLE_TICKS};
    use ev_userspace_contract::root_v5::surface::{Header, Producer};
    let mut model = Model::new();
    let mut presentation = Presentation::new();
    assert!(!model.paintable(1));
    feed(&mut model, &data(1)).unwrap();
    presentation.stats();
    let first = Header {
        producer: Producer::Application,
        instance: 4,
        process: 12,
        thread: 13,
        incarnation: 1,
        surface_object: 14,
        surface_generation: 12,
        frame: 2,
        view_revision: 1,
        model_revision: 3,
        width: 320,
        height: 180,
        stride_bytes: 1280,
        payload_bytes: 230400,
        mapping_epoch: 1,
        protected_scope_nonce: 0,
    };
    presentation.begin(10, first).unwrap();
    presentation.completed(first, true, 100).unwrap();
    feed(&mut model, &data(2)).unwrap();
    presentation.stats();
    assert!(model.paintable(2));
    assert!(!presentation.ready(100 + STATS_IDLE_TICKS - 1));

    model.put(0, false, 3).unwrap();
    model.put(0, true, 0).unwrap();
    assert_eq!(model.snapshot().unwrap().view(), 2);
    assert!(model.collecting());
    assert!(presentation.ready(100 + STATS_IDLE_TICKS));
    assert!(!model.paintable(2) && !model.paintable(3));
    let words = data(3);
    for i in (1..128).filter(|i| field::required(*i as u8) || *i == 127) {
        for high in [false, true] {
            model
                .put(
                    i as u8,
                    high,
                    (words[i] >> if high { 32 } else { 0 }) as u32,
                )
                .unwrap();
            if model.collecting() {
                assert!(!model.paintable(2) && !model.paintable(3));
            }
        }
    }
    presentation.stats();
    assert!(!model.collecting());
    assert!(model.paintable(3) && !model.paintable(2));
    assert!(presentation.ready(101 + STATS_IDLE_TICKS));
    let latest = Header {
        frame: 3,
        view_revision: 3,
        ..first
    };
    presentation.begin(101 + STATS_IDLE_TICKS, latest).unwrap();
    assert_eq!(presentation.accepted(), Some(first));
}
#[test]
fn requests_carry_exact_bounded_view_and_row_but_never_process_authority_or_approval() {
    let mut model = Model::new();
    assert!(model.action(5).is_none());
    feed(&mut model, &data(0xfedc_ba98)).unwrap();
    assert_eq!(
        model.action(5),
        Some(Event::InspectAction {
            action: 5,
            row: 0,
            view: 0xfedc_ba98
        })
    );
    model.select(1);
    assert!(model.action(5).is_none());
    assert_eq!(
        model.action(1),
        Some(Event::InspectAction {
            action: 1,
            row: 0,
            view: 0xfedc_ba98
        })
    );
    assert!(model.action(14).is_none());
    let event = model.action(12).unwrap();
    let raw = event.encode().unwrap();
    assert_eq!(&raw[4..], &0xfedc_ba98u32.to_le_bytes());
    assert_eq!(Event::decode(raw), Ok(event));
}
struct Memory {
    w: usize,
    h: usize,
    bytes: Vec<u32>,
}
impl Pixels for Memory {
    fn dimensions(&self) -> (usize, usize) {
        (self.w, self.h)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), GraphicsError> {
        assert!(x < self.w && y < self.h);
        self.bytes[y * self.w + x] = color.0;
        Ok(())
    }
}
#[test]
fn actual_viewport_never_draws_outside_mapping_and_empty_model_has_no_fake_stats() {
    let mut model = Model::new();
    for (w, h) in [(1, 1), (73, 59), (160, 90), (320, 180), (320, 200)] {
        let mut p = Memory {
            w,
            h,
            bytes: vec![0; w * h],
        };
        render(&mut p, &model, true).unwrap();
        assert_eq!(hit_test(w, h, w, 0), None);
        assert_eq!(hit_test(w, h, 0, h), None);
    }
    assert!(model.snapshot().is_none());
    feed(&mut model, &data(1)).unwrap();
    let mut p = Memory {
        w: 320,
        h: 180,
        bytes: vec![0; 320 * 180],
    };
    render(&mut p, &model, true).unwrap();
    assert_eq!(hit_test(320, 180, 1, 1), Some(1));
    assert_eq!(hit_test(320, 180, 1, 41), Some(11));
    assert_eq!(hit_test(320, 180, 1, 65), Some(100));
}
