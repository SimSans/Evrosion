//! Volatile local identity after actual association and Register. Never remote
//! acceptance, durable retention, lifecycle health or a KnownGood transition.
use super::*;

/// Nonserializable metadata for one immutable reader of one Images owner.
/// Copying it copies no mapping/capability ownership or authorization decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Member {
    owner: u64,
    kernel_slot: usize,
    capability: u64,
    header: [u8; 32],
    content: Content,
}
impl Member {
    pub fn capture<T: Io>(
        images: &Images<T>,
        kernel_slot: usize,
        snapshot: &Snapshot,
        content: Content,
    ) -> Result<Self, Error> {
        let (owner, capability, header) =
            images.registered_binding(kernel_slot).ok_or(Error::Owner)?;
        // Original constructor remains strict about this actual Snapshot and
        // every actual sealed package/descriptor/schema/source identity.
        let _checked = Downloaded::from_images(images, kernel_slot, snapshot, content)?;
        Ok(Self {
            owner,
            kernel_slot,
            capability,
            header,
            content,
        })
    }
    pub const fn kernel_slot(self) -> usize {
        self.kernel_slot
    }
    pub const fn content(self) -> Content {
        self.content
    }
    pub fn slot(self) -> DownloadedSlot {
        match self.content.version {
            2 => DownloadedSlot::B,
            3 => DownloadedSlot::C,
            _ => unreachable!("capture validates the closed downloaded identity"),
        }
    }
    /// Recheck only local immutable identity against this same live Images
    /// owner. This never substitutes a retained receipt for a current Store.
    pub fn check<T: Io>(self, images: &Images<T>) -> Result<(), Error> {
        Downloaded::from_member(images, self).map(drop)
    }
}
impl<'a, T: Io> Downloaded<'a, T> {
    fn from_member(images: &'a Images<T>, member: Member) -> Result<Self, Error> {
        if images.registered_binding(member.kernel_slot)
            != Some((member.owner, member.capability, member.header))
        {
            return Err(Error::Owner);
        }
        let package = images
            .package(member.kernel_slot)
            .map_err(super::image_error)?;
        validate(&package, member.content)?;
        Ok(Self {
            images,
            snapshot: None,
            kernel_slot: member.kernel_slot,
            slot: member.slot(),
            content: member.content,
            package,
        })
    }
}
impl<'a, 'bank, T: Io> View<'a, 'bank, T> {
    /// Explicit local-only alternative. Original `new` still requires exact
    /// Snapshot pointer membership and refuses these retained-origin values.
    pub fn from_members(
        banks: &'a Packages<'bank>,
        images: &'a Images<T>,
        members: [Option<Member>; 2],
    ) -> Result<Self, Error> {
        let mut downloaded = [None, None];
        for (i, member) in members.into_iter().enumerate() {
            if let Some(member) = member {
                downloaded[i] = Some(Downloaded::from_member(images, member)?);
            }
        }
        Self::checked(banks, images, None, downloaded)
    }
}

#[cfg(test)]
mod tests;
