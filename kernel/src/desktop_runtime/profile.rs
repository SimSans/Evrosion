//! Compile-time metadata selection inside the same retained graph executor.
//! Only the explicit V4 feature admits its larger startup and actor graph.
#[cfg(not(feature = "test-m6-network"))]
pub(super) use ev_userspace_contract::root_v2::graph::*;
#[cfg(all(not(feature = "test-m6-network"), feature = "test-m5-native"))]
pub(crate) use ev_userspace_contract::root_v2::native as root_abi;
#[cfg(all(not(feature = "test-m6-network"), feature = "test-m5-native"))]
pub(super) use ev_userspace_contract::root_v2::native::catalogue::Catalogue as NativeCatalogue;
#[cfg(feature = "test-m6-network")]
pub(crate) use ev_userspace_contract::root_v4 as root_abi;
#[cfg(feature = "test-m6-network")]
pub(super) use ev_userspace_contract::root_v4::catalogue::Catalogue as NativeCatalogue;
#[cfg(feature = "test-m6-network")]
pub(super) use ev_userspace_contract::root_v4::graph::{
    CHILDREN, Channel, Child, DeliveryMode, Grant, Source,
};
pub(super) const ACTORS: usize = CHILDREN.len();
pub(super) const SLOTS: usize = ACTORS + 1;
pub(super) const WIRES: usize = if cfg!(feature = "test-m6-network") {
    18
} else {
    16
};
pub(super) const ROOT_GRANTS: usize = if cfg!(feature = "test-m6-network") {
    32
} else {
    24
};
#[cfg(feature = "test-m6-network")]
pub(super) trait WireIndex {
    fn index(self) -> usize;
}
#[cfg(feature = "test-m6-network")]
impl WireIndex for Channel {
    fn index(self) -> usize {
        self.wire_index()
    }
}
pub(super) fn channel(index: usize) -> Option<Channel> {
    #[cfg(feature = "test-m6-network")]
    {
        Channel::from_wire_index(index)
    }
    #[cfg(not(feature = "test-m6-network"))]
    {
        CHANNELS.get(index).copied()
    }
}
#[cfg(feature = "test-m6-network")]
pub(super) struct Grants {
    values: [Grant; 8],
    len: usize,
}
#[cfg(feature = "test-m6-network")]
impl core::ops::Deref for Grants {
    type Target = [Grant];
    fn deref(&self) -> &[Grant] {
        &self.values[..self.len]
    }
}
#[cfg(feature = "test-m6-network")]
pub(super) fn grants(child: Child) -> Grants {
    let mut values = [Grant {
        kind: 1,
        rights: 1,
        source: Source::Root(root_abi::Role::ShellImage),
    }; 8];
    let mut len = 0;
    for value in ev_userspace_contract::root_v4::graph::grants(child) {
        values[len] = value;
        len += 1;
    }
    Grants { values, len }
}
pub(super) fn child_limits(child: Child) -> ev_kernel::scheduler::Limits {
    #[cfg(feature = "test-m6-network")]
    {
        let [a, b, c, d] = child.limits();
        ev_kernel::scheduler::Limits::new(a, b, c, d)
    }
    #[cfg(not(feature = "test-m6-network"))]
    {
        let _ = child;
        super::CHILD_LIMITS
    }
}

#[cfg(feature = "test-m5-native")]
pub(super) fn boot_mode(
    bytes: &[u8],
) -> ev_userspace_contract::root_v2::native::catalogue::BootMode {
    #[cfg(not(feature = "test-m6-network"))]
    {
        NativeCatalogue::decode(bytes).unwrap().boot_mode()
    }
    #[cfg(feature = "test-m6-network")]
    {
        use ev_userspace_contract::{
            root_v2::native::catalogue::BootMode as Old, root_v4::catalogue::BootMode as New,
        };
        match NativeCatalogue::decode(bytes).unwrap().boot_mode() {
            New::Standalone => Old::Standalone,
            New::SystemManaged => Old::SystemManaged,
            New::Recovery => Old::Recovery,
        }
    }
}
