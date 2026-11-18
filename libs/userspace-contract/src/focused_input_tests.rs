use super::*;

#[test]
fn legacy_key_frames_are_exact_and_cursor_extension_is_explicit() {
    for (key, code) in [
        (Key::Tab, 1),
        (Key::Enter, 2),
        (Key::Escape, 3),
        (Key::Up, 4),
        (Key::Down, 5),
        (Key::Left, 6),
        (Key::Right, 7),
    ] {
        let event = KeyEvent {
            key,
            sequence: 0x01020304,
            release_known: false,
            approval_ready: false,
        };
        let bytes = [b'K', 1, code, 0, 4, 3, 2, 1];
        assert_eq!(event.encode(), Ok(bytes));
        assert_eq!(KeyEvent::decode(&bytes, 0), Ok(event));
        assert_eq!(KeyEvent::decode(&bytes, 1), Err(Error::CapabilityCount));
    }
}
#[test]
fn only_released_enter_can_carry_approval_readiness_and_neither_is_authority() {
    for key in [
        Key::Tab,
        Key::Enter,
        Key::Escape,
        Key::Up,
        Key::Down,
        Key::Left,
        Key::Right,
    ] {
        for flags in 0..=255u8 {
            let bytes = [b'K', 1, key as u8, flags, 1, 0, 0, 0];
            assert_eq!(
                KeyEvent::decode(&bytes, 0).is_ok(),
                if key == Key::Enter {
                    matches!(flags, 0 | 1 | 3)
                } else {
                    flags == 0
                }
            );
        }
    }
    for n in [0, u32::MAX] {
        let mut b = [b'K', 1, 1, 0, 0, 0, 0, 0];
        b[4..].copy_from_slice(&n.to_le_bytes());
        assert_eq!(KeyEvent::decode(&b, 0), Err(Error::Sequence));
    }
    for n in 0..8 {
        assert_eq!(KeyEvent::decode(&[0; 8][..n], 0), Err(Error::Length));
    }
}
