//! Two fixed guarded RAM-surface windows within the existing private 2 MiB leaf.
//! This describes layout only, never a frame claim, capability or live mapping.
use crate::{executable::Image, memory::FRAME_SIZE};

pub const PAGES: usize = 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    Primary,
    Auxiliary,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    PrivateOverlap,
}
impl Window {
    pub const fn first(self) -> usize {
        match self {
            Self::Primary => 384,
            Self::Auxiliary => 304,
        }
    }
    pub const fn lower_guard(self) -> usize {
        self.first() - 1
    }
    pub const fn upper_guard(self) -> usize {
        self.first() + PAGES
    }
    pub fn readable_entry(self, index: usize) -> bool {
        (self.lower_guard()..=self.upper_guard()).contains(&index)
    }
    pub fn writable_entry(self, index: usize) -> bool {
        (self.first()..self.first() + PAGES).contains(&index)
    }
    fn conflicts(self, base: u64, address: u64) -> bool {
        address.checked_sub(base).is_some_and(|offset| {
            let page = offset / FRAME_SIZE;
            (self.lower_guard() as u64..=self.upper_guard() as u64).contains(&page)
        })
    }
    /// Check the actual immutable measured ELF plan, including each private
    /// LOAD page, its independent startup page and the ordinary stack. An unused
    /// auxiliary window is not silently reserved for legacy images.
    pub fn verify_private(self, image: &Image<'_>) -> Result<(), Error> {
        if image
            .pages()
            .any(|page| self.conflicts(image.base(), page.address))
            || self.conflicts(image.base(), image.stack_page())
            || image
                .bootstrap_page()
                .is_some_and(|page| self.conflicts(image.base(), page))
        {
            Err(Error::PrivateOverlap)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        capability::{Kind, Rights},
        scheduler::Limits,
        service::{Role, ServiceImage},
    };
    use sha2::{Digest, Sha256};

    #[test]
    fn windows_are_disjoint_fixed_63_pages_and_neither_guard_is_writable() {
        for window in [Window::Primary, Window::Auxiliary] {
            assert_eq!(
                (0..512).filter(|page| window.writable_entry(*page)).count(),
                PAGES
            );
            assert!(window.readable_entry(window.lower_guard()));
            assert!(window.readable_entry(window.upper_guard()));
            assert!(!window.writable_entry(window.lower_guard()));
            assert!(!window.writable_entry(window.upper_guard()));
            assert!(!window.readable_entry(usize::MAX));
        }
        for page in 0..512 {
            assert!(
                !(Window::Primary.readable_entry(page) && Window::Auxiliary.readable_entry(page))
            );
        }
        // The measured desktop stacks occupy256..259 with independent guards.
        for page in 255..=260 {
            assert!(!Window::Primary.readable_entry(page));
            assert!(!Window::Auxiliary.readable_entry(page));
        }
    }
    #[test]
    fn actual_measured_load_on_either_surface_or_guard_is_rejected_before_mapping() {
        const ELF: &[u8] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
        for page in [302, 303, 304, 366, 367, 368, 382, 383, 384, 446, 447, 448] {
            let mut bytes = ELF.to_vec();
            let address = (1u64 << 39) + page * FRAME_SIZE;
            // Keep text/entry first and relocate the second actual RW LOAD as
            // exactly one page, preserving canonical program-header ordering.
            bytes[136..144].copy_from_slice(&address.to_le_bytes());
            bytes[160..168].copy_from_slice(&FRAME_SIZE.to_le_bytes());
            let descriptor = ServiceImage::verify(
                &bytes,
                Sha256::digest(&bytes).into(),
                Limits::new(2048, 32, 1, 1),
                &[Role {
                    selector: 1,
                    kind: Kind::Memory,
                    rights: Rights::READ,
                }],
            )
            .unwrap();
            let image = descriptor.plan().unwrap();
            for window in [Window::Primary, Window::Auxiliary] {
                assert_eq!(
                    window.verify_private(&image),
                    if window.readable_entry(page as usize) {
                        Err(Error::PrivateOverlap)
                    } else {
                        Ok(())
                    }
                );
            }
        }
    }
}
