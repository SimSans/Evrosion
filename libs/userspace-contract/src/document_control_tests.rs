use super::*;

#[test]
fn directions_nonce_choice_access_and_capability_count_are_separate() {
    for (op, tag) in [
        (Operation::OpenRead, 1),
        (Operation::OpenEdit, 2),
        (Operation::Publish, 3),
    ] {
        let request = Request::new(op, 0x01020304).unwrap();
        assert_eq!(request.encode(), [b'D', b'C', 1, tag, 4, 3, 2, 1]);
        assert_eq!(Request::decode(&request.encode(), 0), Ok(request));
        let reply = request.reply(Outcome::Published);
        assert_eq!(Reply::decode(&reply.encode(), 0), Ok(reply));
        assert_eq!(Reply::decode(&request.encode(), 0), Err(Error::Magic));
        assert_eq!(Request::decode(&reply.encode(), 0), Err(Error::Magic));
        assert_eq!(
            Request::decode(&request.encode(), 1),
            Err(Error::CapabilityCount)
        );
    }
    for choice in [Choice::Notes, Choice::Private] {
        for access in [Access::Read, Access::Edit] {
            let grant = Granted::new(7, choice, access).unwrap();
            assert_eq!(Granted::decode(&grant.encode(), 1), Ok(grant));
            assert_eq!(
                Granted::decode(&grant.encode(), 0),
                Err(Error::CapabilityCount)
            );
            assert_eq!(
                Granted::decode(&grant.encode(), 2),
                Err(Error::CapabilityCount)
            );
            assert_eq!(Request::decode(&grant.encode(), 0), Err(Error::Magic));
        }
    }
    assert_eq!(
        Granted::new(1, Choice::None, Access::Edit),
        Err(Error::Choice)
    );
    assert_eq!(
        Granted::new(1, Choice::Notes, Access::None),
        Err(Error::Access)
    );
}

#[test]
fn picker_intent_has_explicit_rights_and_a_trusted_root_serial() {
    for (access, opcode) in [(Access::Read, 19), (Access::Edit, 20)] {
        let picker = Picker { access, serial: 17 };
        let bytes = picker.encode().unwrap();
        assert_eq!(bytes, [b'R', opcode, 0, 0, 17, 0, 0, 0]);
        assert_eq!(Picker::decode(&bytes, 0), Ok(picker));
        assert_eq!(Picker::decode(&bytes, 1), Err(Error::CapabilityCount));
        for index in [0, 2, 3] {
            let mut bad = bytes;
            bad[index] ^= 1;
            assert!(Picker::decode(&bad, 0).is_err());
        }
    }
    assert_eq!(
        Picker {
            access: Access::None,
            serial: 1
        }
        .encode(),
        Err(Error::Access)
    );
    assert_eq!(
        Picker {
            access: Access::Edit,
            serial: u32::MAX
        }
        .encode(),
        Err(Error::Nonce)
    );
}

#[test]
fn malformed_length_version_nonce_and_tags_fail_before_use() {
    let request = Request::new(Operation::OpenEdit, 1).unwrap().encode();
    for len in 0..8 {
        assert_eq!(Request::decode(&request[..len], 0), Err(Error::Length));
    }
    assert_eq!(Request::decode(&[0; 9], 0), Err(Error::Length));
    for nonce in [0, u32::MAX] {
        assert_eq!(Request::new(Operation::Publish, nonce), Err(Error::Nonce));
        let mut bad = request;
        bad[4..].copy_from_slice(&nonce.to_le_bytes());
        assert_eq!(Request::decode(&bad, 0), Err(Error::Nonce));
    }
    for (index, value, error) in [
        (0, 0, Error::Magic),
        (2, 2, Error::Version),
        (3, 4, Error::Tag),
    ] {
        let mut bad = request;
        bad[index] = value;
        assert_eq!(Request::decode(&bad, 0), Err(error));
    }
    let good = Granted::new(1, Choice::Notes, Access::Edit)
        .unwrap()
        .encode();
    for value in 0..=255u8 {
        let mut candidate = good;
        candidate[3] = value;
        assert_eq!(
            Granted::decode(&candidate, 1).is_ok(),
            matches!(value, 0x11 | 0x12 | 0x21 | 0x22)
        );
    }
}

#[test]
fn bounded_arbitrary_control_messages_decode_totally_and_canonically() {
    let mut random = 0x7b918cadu32;
    for _ in 0..4096 {
        let mut bytes = [0; 8];
        for byte in &mut bytes {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            *byte = random as u8;
        }
        if let Ok(r) = Request::decode(&bytes, 0) {
            assert_eq!(r.encode(), bytes);
        }
        if let Ok(r) = Reply::decode(&bytes, 0) {
            assert_eq!(r.encode(), bytes);
        }
        if let Ok(r) = Granted::decode(&bytes, 1) {
            assert_eq!(r.encode(), bytes);
        }
        if let Ok(r) = Picker::decode(&bytes, 0) {
            assert_eq!(r.encode().unwrap(), bytes);
        }
    }
}
