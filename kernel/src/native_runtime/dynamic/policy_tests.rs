#[path = "policy.rs"]
mod policy;
use ev_kernel::mapping::{ADDRESS_MASK, NO_EXECUTE, PRESENT, WRITABLE};
use policy::{Error, Window};
fn table(window: Window, pages: usize) -> [u64; 512] {
    let mut b = [0; 512];
    let first = window.first().unwrap();
    for (i, p) in b[first..first + pages].iter_mut().enumerate() {
        *p = (0x100000 + i as u64 * 4096)
            | PRESENT
            | 4
            | NO_EXECUTE
            | if window == Window::Writer {
                WRITABLE
            } else {
                0
            }
    }
    b
}
fn check(b: &[u64; 512], w: Window, n: usize, installed: bool) -> Result<(), Error> {
    policy::retained(|i| Ok(b[i]), w, 0x100000, n, installed)
}
#[test]
fn exact_partial_and_complete_receipts_never_accept_foreign_physical_or_permission_rows() {
    for window in [Window::Writer, Window::Reader(0), Window::Reader(1)] {
        let b = table(window, 64);
        assert_eq!(check(&b, window, 64, true), Ok(()));
        for i in window.first().unwrap()..window.first().unwrap() + 64 {
            for bit in [0, 1, 2, 8, 12, 63] {
                let mut bad = b;
                bad[i] ^= 1 << bit;
                assert!(check(&bad, window, 64, true).is_err());
                assert!(check(&bad, window, 64, false).is_err());
            }
            let mut partial = b;
            partial[i] = 0;
            assert_eq!(check(&partial, window, 64, false), Ok(()));
            assert!(check(&partial, window, 64, true).is_err());
        }
        let mut ad = b;
        for p in &mut ad[window.first().unwrap()..window.first().unwrap() + 64] {
            *p |= (1 << 5) | (1 << 6)
        }
        assert_eq!(check(&ad, window, 64, true), Ok(()));
    }
}
#[test]
fn every_tail_guard_zero_and_reader_capacity_refuses_before_any_write() {
    for w in [Window::Writer, Window::Reader(0), Window::Reader(1)] {
        let b = table(w, 1);
        let copy = b;
        assert_eq!(check(&b, w, 1, true), Ok(()));
        for i in w.first().unwrap() - 1..=w.first().unwrap() + 64 {
            if i == w.first().unwrap() {
                continue;
            }
            let mut bad = b;
            for value in [PRESENT | NO_EXECUTE, 1 << 5, 1 << 6] {
                bad[i] = value;
                assert!(check(&bad, w, 1, true).is_err());
                assert!(check(&bad, w, 1, false).is_err());
            }
        }
        assert_eq!(b, copy);
        assert_eq!(check(&b, w, 0, true), Err(Error::Bounds));
        assert_eq!(check(&b, w, 65, true), Err(Error::Bounds));
    }
    assert_eq!(Window::Reader(2).first(), Err(Error::Bounds));
    assert!(policy::retained(|_| Ok(0), Window::Writer, ADDRESS_MASK, 2, false).is_err());
    assert!(policy::retained(|_| Ok(0), Window::Writer, 0, 1, false).is_err());
}
#[test]
fn empty_window_and_failed_actual_read_are_not_mutation_or_quiescence_acknowledgements() {
    let mut b = [0; 512];
    assert_eq!(policy::empty(|i| Ok(b[i]), Window::Writer), Ok(()));
    b[256] = PRESENT;
    assert!(policy::empty(|i| Ok(b[i]), Window::Writer).is_err());
    assert_eq!(
        policy::retained(|_| Err(Error::Read), Window::Reader(0), 0x100000, 1, false),
        Err(Error::Read)
    );
}
