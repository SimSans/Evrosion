//! Closed selected service load classes. No packet supplies page/frame limits.
//! These metadata checks allocate no RAM; physical ownership remains external.
use super::*;
use ev_userspace_contract::root_v5::{self as v5, graph::ImageSlot, resources};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceProfile {
    Ui = 1,
    Workspace = 2,
    Editor = 3,
    Display = 4,
}
impl ServiceProfile {
    pub const fn for_slot(slot: ImageSlot) -> Option<Self> {
        match resources::image_layout(slot) {
            resources::ImageLayout::LegacyCore => None,
            resources::ImageLayout::Ui => Some(Self::Ui),
            resources::ImageLayout::Workspace => Some(Self::Workspace),
            resources::ImageLayout::Editor => Some(Self::Editor),
            resources::ImageLayout::Display => Some(Self::Display),
        }
    }
    pub const fn max_image_pages(self) -> usize {
        match self {
            Self::Ui | Self::Workspace => 96,
            Self::Editor => 384,
            Self::Display => 80,
        }
    }
    pub const fn max_private_pages(self) -> usize {
        self.max_image_pages() + 4
    }
    pub const fn max_loader_frames(self) -> u64 {
        self.max_image_pages() as u64
            + 6
            + match self {
                Self::Display => DISPLAY_TABLE_FRAMES,
                _ => 0,
            }
    }
    pub const fn layout(self) -> LayoutReservation {
        match self {
            Self::Display => LayoutReservation::DisplayApertureV1,
            _ => LayoutReservation::Legacy,
        }
    }
    pub const fn startup_layout(self) -> StartupLayout {
        match self {
            Self::Workspace | Self::Display => StartupLayout::ServiceV5,
            _ => StartupLayout::ServiceV1,
        }
    }
    /// Normalized finite policy transcript for the distinct measured descriptor.
    pub const fn values(self) -> [u64; 13] {
        [
            self as u64,
            self.max_image_pages() as u64,
            self.max_private_pages() as u64,
            self.max_loader_frames(),
            512,
            480,
            8,
            479,
            488,
            509,
            511,
            self.startup_layout().bytes().unwrap() as u64,
            self.layout().additional_table_frames(),
        ]
    }
    fn reserved(self, page: u64) -> bool {
        if matches!(page, 479 | 488) || page >= 509 {
            return true;
        }
        match self {
            Self::Ui | Self::Editor => (383..=447).contains(&page) || (505..=508).contains(&page),
            Self::Workspace => (493..=509).contains(&page),
            Self::Display => resources::DISPLAY_SURFACES
                .iter()
                .any(|(_, first, count)| page >= first - 1 && page <= first + count),
        }
    }
    fn validate(self, image: &Image<'_>) -> Result<(), Error> {
        let mut stack = 0;
        for page in image.pages() {
            let relative = (page.address - image.base()) / FRAME_SIZE;
            if self.reserved(relative) {
                return Err(Error::Address);
            }
            if (480..488).contains(&relative) {
                if page.permission != UserPermission::ReadWrite
                    || page.initialized.iter().any(|b| *b != 0)
                {
                    return Err(Error::Permission);
                }
                stack += 1;
            }
        }
        if stack != 8 {
            return Err(Error::Address);
        }
        Ok(())
    }
}

pub(super) fn plan<'a>(
    bytes: &'a [u8],
    descriptor: [u8; 32],
    slot: ImageSlot,
    limits: crate::scheduler::Limits,
) -> Result<Image<'a>, Error> {
    let Some(profile) = ServiceProfile::for_slot(slot) else {
        return Image::from_descriptor(bytes, descriptor, ev_userspace_contract::ABI, limits);
    };
    let mut image = parse_with_limit(bytes, descriptor, profile.max_image_pages())?;
    image.layout = profile.layout();
    image.bootstrap = profile.startup_layout();
    profile.validate(&image)?;
    if image.required_frames() > profile.max_loader_frames()
        || image.required_frames() > limits.limit(crate::scheduler::Resource::Frames)
    {
        return Err(Error::FrameBudget);
    }
    // SDK and kernel independently encode the same selected envelopes.
    if resources::max_image_pages(slot) != profile.max_image_pages() as u64
        || resources::max_private_pages(slot) != profile.max_private_pages() as u64
        || resources::max_loader_frames(slot) != profile.max_loader_frames()
        || v5::child::startup_size(slot.representative()) != image.startup_layout().bytes().unwrap()
    {
        return Err(Error::Unsupported);
    }
    Ok(image)
}

#[cfg(test)]
pub(crate) mod tests;
