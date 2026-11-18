//! Nominal conversion for the explicitly selected current QEMU PIT profile.
//! Kernel timer.rs programs divisor1193; QEMU v10.2.1 i8254.h defines1193182Hz.
//! Delivered IRQ ticks are not trusted UTC, a wall-clock guarantee across VM
//! pause/lost interrupts, or an entropy source. M6-05 qualification stays open.
pub const PIT_DIVISOR: u64 = 1193;
pub const PIT_INPUT_HZ: u64 = 1_193_182;

pub fn nominal_millis(ticks: u64) -> u64 {
    // The numerator/denominator ratio is less than1ms/tick; this widened
    // intermediate and checked conversion cannot wrap even at u64::MAX.
    u64::try_from(u128::from(ticks) * u128::from(PIT_DIVISOR) * 1000 / u128::from(PIT_INPUT_HZ))
        .unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_profile_conversion_is_monotonic_and_does_not_invent_ten_ms_ticks() {
        assert_eq!(nominal_millis(0), 0);
        assert_eq!(nominal_millis(1000), 999);
        assert_eq!(nominal_millis(PIT_INPUT_HZ), PIT_DIVISOR * 1000);
        assert!(nominal_millis(u64::MAX) < u64::MAX);
        for tick in [1, 2, 999, 1000, 1_000_000, u64::MAX - 1] {
            assert!(nominal_millis(tick) <= nominal_millis(tick + 1));
        }
    }
}
