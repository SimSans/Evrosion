//! Exact int80 register outputs shared by scalar and four-output handlers.
//! Legacy scalar calls preserve R10; nonce/event operations explicitly own it.
use ev_kernel::user_context::UserContext;
pub(super) fn scalar(frame: &mut UserContext, status: u64, value: u64) {
    frame.registers[14] = status;
    frame.registers[9] = value;
    frame.registers[11] = 0;
}
pub(super) fn extended(frame: &mut UserContext, status: u64, value: u64, serial: u64) {
    scalar(frame, status, value);
    frame.registers[5] = serial;
}
pub(super) fn process_identity(frame: &mut UserContext, process: u64, thread: u64) {
    scalar(frame, 0, process);
    frame.registers[11] = thread;
}
pub(super) fn event(frame: &mut UserContext, body: u64, process: u64, thread: u64) {
    extended(frame, 0, body, thread);
    frame.registers[11] = process;
}
pub(super) fn receive_error(frame: &mut UserContext, four_outputs: bool, status: u64) {
    if four_outputs {
        extended(frame, status, 0, 0);
    } else {
        scalar(frame, status, 0);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn frame() -> UserContext {
        let mut frame = UserContext::new(0x8000001000, 0x8000104000).unwrap();
        frame.vector = 128;
        frame.registers = core::array::from_fn(|i| 0xcafe_1234_0000_0000 + i as u64);
        frame
    }
    fn changed_only(before: &UserContext, after: &UserContext, changed: &[usize]) {
        for index in 0..15 {
            if !changed.contains(&index) {
                assert_eq!(
                    before.registers[index], after.registers[index],
                    "register{index}"
                );
            }
        }
        assert_eq!(
            (
                before.vector,
                before.error,
                before.rip,
                before.cs,
                before.flags,
                before.rsp,
                before.ss
            ),
            (
                after.vector,
                after.error,
                after.rip,
                after.cs,
                after.flags,
                after.rsp,
                after.ss
            )
        );
    }
    #[test]
    fn scalar_success_and_refusal_preserve_r10_and_every_undeclared_register() {
        for status in [0, 1, 2, 4] {
            let before = frame();
            let mut after = before;
            scalar(&mut after, status, 91);
            changed_only(&before, &after, &[14, 9, 11]);
            assert_eq!(
                (after.registers[14], after.registers[9], after.registers[11]),
                (status, 91, 0)
            );
            assert_eq!(after.registers[5], before.registers[5]);
        }
    }
    #[test]
    fn receive_rpc_returns_nonce_in_r10_with_rdx_zero_and_errors_clear_four_outputs() {
        let before = frame();
        let mut after = before;
        extended(&mut after, 0, 0x1234, 17);
        changed_only(&before, &after, &[14, 9, 11, 5]);
        assert_eq!(
            (
                after.registers[14],
                after.registers[9],
                after.registers[11],
                after.registers[5]
            ),
            (0, 0x1234, 0, 17)
        );
        for status in [1, 2, 4] {
            let mut after = before;
            extended(&mut after, status, 0, 0);
            changed_only(&before, &after, &[14, 9, 11, 5]);
            assert_eq!(
                (
                    after.registers[14],
                    after.registers[9],
                    after.registers[11],
                    after.registers[5]
                ),
                (status, 0, 0, 0)
            );
        }
    }
    #[test]
    fn process_identity_is_legacy_pid_tid_output_and_preserves_r10_canary() {
        let before = frame();
        let mut after = before;
        process_identity(&mut after, 258, 514);
        changed_only(&before, &after, &[14, 9, 11]);
        assert_eq!(
            (
                after.registers[14],
                after.registers[9],
                after.registers[11],
                after.registers[5]
            ),
            (0, 258, 514, before.registers[5])
        );
    }
    #[test]
    fn receive_event_and_legacy_receive_have_distinct_success_and_error_clobbers() {
        let before = frame();
        let mut after = before;
        event(&mut after, 0x1234, 258, 514);
        changed_only(&before, &after, &[14, 9, 11, 5]);
        assert_eq!(
            (after.registers[9], after.registers[11], after.registers[5]),
            (0x1234, 258, 514)
        );
        for four in [false, true] {
            for status in [1, 2] {
                let mut after = before;
                receive_error(&mut after, four, status);
                changed_only(
                    &before,
                    &after,
                    if four { &[14, 9, 11, 5] } else { &[14, 9, 11] },
                );
                assert_eq!(
                    after.registers[5],
                    if four { 0 } else { before.registers[5] }
                );
                assert_eq!(
                    (after.registers[14], after.registers[9], after.registers[11]),
                    (status, 0, 0)
                );
            }
        }
    }
    #[test]
    fn matched_reply_wakes_caller_without_clobbering_its_saved_r10_and_clears_replier_nonce() {
        let mut caller = frame();
        let original = caller;
        scalar(&mut caller, 0, 0);
        scalar(&mut caller, 0, 0xfeed);
        changed_only(&original, &caller, &[14, 9, 11]);
        assert_eq!(caller.registers[5], original.registers[5]);
        assert_eq!(caller.registers[9], 0xfeed);
        let mut callee = frame();
        callee.registers[5] = 17;
        let original = callee;
        extended(&mut callee, 0, 0, 0);
        changed_only(&original, &callee, &[14, 9, 11, 5]);
        assert_eq!(
            (
                callee.registers[14],
                callee.registers[9],
                callee.registers[11],
                callee.registers[5]
            ),
            (0, 0, 0, 0)
        );
    }
}
