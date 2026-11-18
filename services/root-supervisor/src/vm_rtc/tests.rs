use super::*;
extern crate std;
use std::vec::Vec;
struct Device {
    rows: Vec<(u8, u8)>,
    at: usize,
    tick: u64,
    advance: u64,
    fail: Option<usize>,
}
impl Io for Device {
    fn tick(&mut self) -> u64 {
        let n = self.tick;
        self.tick = self.tick.saturating_add(self.advance);
        n
    }
    fn read(&mut self, r: u8, _cut: u64) -> Result<u8, Error> {
        if self.fail == Some(self.at) {
            return Err(Error::Unavailable);
        }
        let (register, value) = self.rows[self.at];
        self.at += 1;
        assert_eq!(r, register);
        Ok(value)
    }
}
fn rows(v: [u8; 8]) -> Vec<(u8, u8)> {
    let mut x = std::vec![(10, 0x26), (13, 0x80), (11, v[0])];
    x.extend(
        [0, 2, 4, 7, 8, 9, RTC_CENTURY]
            .into_iter()
            .zip(v[1..].iter().copied()),
    );
    x.extend([(11, v[0]), (10, 0x26), (13, 0x80)]);
    x
}
fn device(v: [u8; 8]) -> Device {
    let mut x = rows(v);
    x.extend(rows(v));
    Device {
        rows: x,
        at: 0,
        tick: 1,
        advance: 0,
        fail: None,
    }
}
const BCD: [u8; 8] = [2, 0x56, 0x34, 0x12, 0x29, 0x02, 0x24, 0x20];
#[test]
fn coherent_bcd_binary_12h_and_real_calendar_rollover_agree() {
    let b = calendar(BCD).unwrap();
    assert_eq!(b, calendar([6, 56, 34, 12, 29, 2, 24, 20]).unwrap());
    assert_eq!(
        b,
        calendar([0, 0x56, 0x34, 0x92, 0x29, 0x02, 0x24, 0x20]).unwrap()
    );
    assert_eq!(
        calendar([0, 0, 0, 0x12, 1, 1, 0x26, 0x20]).unwrap() + 43200,
        calendar([0, 0, 0, 0x92, 1, 1, 0x26, 0x20]).unwrap()
    );
    let mut c = Clock::new();
    assert_eq!(c.sample(&mut device(BCD)).unwrap().elapsed_seconds, 0);
    let mut next = BCD;
    next[1] = 0x57;
    assert_eq!(c.sample(&mut device(next)).unwrap().elapsed_seconds, 1);
    let last = calendar([2, 0x59, 0x59, 0x23, 0x31, 0x12, 0x99, 0x19]).unwrap();
    assert_eq!(last + 1, calendar([2, 0, 0, 0, 1, 1, 0, 0x20]).unwrap());
}
#[test]
fn malformed_bcd_gregorian_dates_modes_and_port_failures_never_return_a_sample() {
    for (at, value) in [
        (1, 0x6a),
        (2, 0x60),
        (3, 0x24),
        (4, 0),
        (4, 0x30),
        (5, 0x13),
        (6, 0xfa),
        (7, 0),
    ] {
        let mut v = BCD;
        v[at] = value;
        assert_eq!(calendar(v), Err(Error::Calendar));
    }
    let mut v = BCD;
    v[6] = 0;
    v[7] = 0x21;
    assert_eq!(calendar(v), Err(Error::Calendar)); //2100 isnotleap
    let mut d = device(BCD);
    d.rows[2].1 |= 0x80;
    assert_eq!(Clock::new().sample(&mut d), Err(Error::Configuration));
    let mut d = device(BCD);
    d.rows[0].1 = 0x66;
    assert_eq!(Clock::new().sample(&mut d), Err(Error::Configuration));
    let mut d = device(BCD);
    d.fail = Some(5);
    let mut c = Clock::new();
    assert_eq!(c.sample(&mut d), Err(Error::Unavailable));
    assert_eq!(c.sample(&mut device(BCD)), Err(Error::Failed));
}
#[test]
fn changing_snapshot_uip_and_nonrunning_source_are_bounded() {
    let mut next = BCD;
    next[1] = 0x57;
    let mut d = device(BCD);
    d.rows = rows(BCD);
    d.rows.extend(rows(next));
    d.rows.extend(rows(next));
    assert!(Clock::new().sample(&mut d).is_ok());
    let mut d = device(BCD);
    d.rows = std::vec![(10,0xa6);RTC_UIP_POLLS*RTC_MAX_SNAPSHOTS];
    assert_eq!(Clock::new().sample(&mut d), Err(Error::Inconsistent));
    assert_eq!(d.at, RTC_UIP_POLLS * RTC_MAX_SNAPSHOTS);
    let mut d = device(BCD);
    d.rows[1].1 = 0;
    assert_eq!(Clock::new().sample(&mut d), Err(Error::Unavailable));
    let mut d = device(BCD);
    d.rows = rows(BCD);
    d.rows.extend(rows(next));
    d.rows.extend(rows(BCD));
    d.rows.extend(rows(next));
    assert_eq!(Clock::new().sample(&mut d), Err(Error::Inconsistent));
}
#[test]
fn original_cut_post_read_expiry_clock_regression_and_overflow_fence_forever() {
    let mut d = device(BCD);
    d.advance = 128;
    let mut c = Clock::new();
    assert_eq!(c.sample(&mut d), Err(Error::Deadline));
    assert!(d.at < 3);
    assert_eq!(c.sample(&mut device(BCD)), Err(Error::Failed));
    let mut c = Clock::new();
    let mut d = device(BCD);
    d.tick = 100;
    assert!(c.sample(&mut d).is_ok());
    let mut d = device(BCD);
    d.tick = 99;
    assert_eq!(c.sample(&mut d), Err(Error::Clock));
    let mut c = Clock::new();
    let mut d = device(BCD);
    d.tick = u64::MAX - 511;
    assert_eq!(c.sample(&mut d), Err(Error::Overflow));
    let mut c = Clock::new();
    assert!(c.sample(&mut device(BCD)).is_ok());
    let mut older = BCD;
    older[1] = 0x55;
    assert_eq!(c.sample(&mut device(older)), Err(Error::Clock));
}
