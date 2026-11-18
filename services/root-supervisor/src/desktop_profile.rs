//! Compile-time typed Source Root profile. Metadata stays a borrowed view of
//! the selected validated bytes; V4 Components never become a legacy App6 proof.
#[cfg(not(feature = "native-network"))]
pub use ev_userspace_contract::root_v2::{Role, catalogue::Catalogue, graph};
#[cfg(feature = "native-network")]
pub use ev_userspace_contract::root_v4::{Role, graph};
pub use graph::{Channel, Child, Source};
pub const CHILD_COUNT: usize = graph::CHILDREN.len();
pub const CHANNEL_SLOTS: usize = if cfg!(feature = "native-network") {
    18
} else {
    15
};
#[cfg(all(feature = "native-root", not(feature = "native-network")))]
pub use ev_userspace_contract::root_v2::native::{
    FullGraph as NativeFullGraph, SIZE as STARTUP_SIZE, catalogue::SIZE as CATALOGUE_SIZE,
};
#[cfg(feature = "native-network")]
pub use ev_userspace_contract::root_v4::{
    FullGraph as NativeFullGraph, SIZE as STARTUP_SIZE, catalogue::SIZE as CATALOGUE_SIZE,
};
#[cfg(feature = "native-network")]
pub trait WireIndex {
    fn index(self) -> usize;
}
#[cfg(feature = "native-network")]
impl WireIndex for Channel {
    fn index(self) -> usize {
        self.wire_index()
    }
}
#[cfg(feature = "native-network")]
pub struct Catalogue<'a>(ev_userspace_contract::root_v4::catalogue::Catalogue<'a>);
#[cfg(feature = "native-network")]
impl<'a> Catalogue<'a> {
    pub fn from_network(
        catalogue: ev_userspace_contract::root_v4::catalogue::Catalogue<'a>,
    ) -> Self {
        Self(catalogue)
    }
}
#[cfg(feature = "native-network")]
impl<'a> core::ops::Deref for Catalogue<'a> {
    type Target = ev_userspace_contract::root_v2::catalogue::Components<'a>;
    fn deref(&self) -> &Self::Target {
        self.0.base()
    }
}
pub fn grants(child: Child) -> impl Iterator<Item = graph::Grant> {
    #[cfg(feature = "native-network")]
    {
        graph::grants(child)
    }
    #[cfg(not(feature = "native-network"))]
    {
        graph::grants(child).iter().copied()
    }
}
/// A selected graph template narrows the existing Root creator; it grants no
/// caller-chosen limits. The Kernel resolves and checks the same measured ID.
pub const fn job_template(child: Child) -> u64 {
    #[cfg(feature = "native-network")]
    {
        child.job_template()
    }
    #[cfg(not(feature = "native-network"))]
    {
        let _ = child;
        0
    }
}
pub const fn network_child(child: Child) -> bool {
    #[cfg(feature = "native-network")]
    {
        matches!(child, Child::NetDriver | Child::NetService)
    }
    #[cfg(not(feature = "native-network"))]
    {
        let _ = child;
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channel_namespace_preserves_events_hole_and_child_scope() {
        for channel in graph::CHANNELS {
            assert!(channel.index() < CHANNEL_SLOTS);
        }
        #[cfg(feature = "native-network")]
        {
            assert_eq!(CHILD_COUNT, 8);
            assert!(!graph::CHANNELS.iter().any(|c| c.index() == 15));
            assert_eq!(Channel::NetDriverRpc.index(), 16);
            assert_eq!(Channel::NetClientRpc.index(), 17);
            assert!(network_child(Child::NetDriver));
            assert!(network_child(Child::NetService));
            assert_eq!(job_template(Child::NetService), 1);
            for child in graph::CHILDREN {
                assert_eq!(
                    child.limits(),
                    ev_userspace_contract::root_v4::JOB_TEMPLATE_LIMITS
                        [job_template(child) as usize]
                );
                if child != Child::NetService {
                    assert_eq!(job_template(child), 0);
                }
            }
        }
        #[cfg(not(feature = "native-network"))]
        {
            assert_eq!(CHILD_COUNT, 6);
        }
        assert!(!network_child(Child::App));
    }
}
