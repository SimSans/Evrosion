//! Kernel-executed table proof, before any userspace capability ABI is exposed.
use ev_kernel::capability::{Authority, Error, Kind, Rights};
pub fn prove() {
    let mut authority = Authority::new();
    let owner = authority.create_space().unwrap();
    let other = authority.create_space().unwrap();
    let rights = Rights::READ
        | Rights::WRITE
        | Rights::DERIVE
        | Rights::TRANSFER
        | Rights::REVOKE
        | Rights::CONTROL;
    let root = authority.create_root(owner, Kind::Memory, rights).unwrap();
    assert_eq!(
        authority
            .authorize(other, root, Kind::Memory, Rights::READ)
            .err(),
        Some(Error::InvalidHandle)
    );
    let read = authority.derive(owner, root, other, Rights::READ).unwrap();
    assert!(
        authority
            .authorize(other, read, Kind::Memory, Rights::READ)
            .is_ok()
    );
    assert_eq!(
        authority
            .authorize(other, read, Kind::Memory, Rights::WRITE)
            .err(),
        Some(Error::Denied)
    );
    assert_eq!(
        authority.derive(other, read, owner, Rights::WRITE),
        Err(Error::Denied)
    );
    let branch = authority
        .derive(
            owner,
            root,
            other,
            Rights::READ | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
        )
        .unwrap();
    let leaf = authority
        .derive(other, branch, other, Rights::READ)
        .unwrap();
    let moved = authority.transfer(other, branch, owner).unwrap();
    assert_eq!(
        authority
            .authorize(other, branch, Kind::Memory, Rights::READ)
            .err(),
        Some(Error::InvalidHandle)
    );
    authority.revoke(owner, moved).unwrap();
    assert_eq!(
        authority
            .authorize(other, leaf, Kind::Memory, Rights::READ)
            .err(),
        Some(Error::Revoked)
    );
    assert!(
        authority
            .authorize(other, read, Kind::Memory, Rights::READ)
            .is_ok()
    );
    authority.close(other, read).unwrap();
    let replacement = authority.derive(owner, root, other, Rights::READ).unwrap();
    assert_ne!(replacement, read);
    assert_eq!(
        authority
            .authorize(other, read, Kind::Memory, Rights::READ)
            .err(),
        Some(Error::InvalidHandle)
    );
    authority.destroy(owner, root).unwrap();
    assert_eq!(
        authority
            .authorize(other, replacement, Kind::Memory, Rights::READ)
            .err(),
        Some(Error::DeadObject)
    );
}
