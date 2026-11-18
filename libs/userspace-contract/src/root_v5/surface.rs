//! Variable geometry is a separate V5 surface header. The legacy fixed v1
//! parser/bytes stay unchanged. Claimed owners/IDs never authenticate a producer.
use super::{Error, put, word};
pub const SIZE: usize = 256;
pub const APP_PIXEL_OFFSET: usize = 256;
/// Root-only registration/control may use256..512 while no Present read credit
/// exists. Root must serialize that use with its separately protected pixels.
pub const ROOT_PIXEL_OFFSET: usize = 512;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Producer {
    Application = 1,
    Shell = 2,
    ProtectedRoot = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub producer: Producer,
    pub instance: u16,
    pub process: u64,
    pub thread: u64,
    pub incarnation: u64,
    /// Descriptive logical source ID fixed by Root's registration. This is not
    /// a raw kernel object lookup or a grant derived from packet metadata.
    pub surface_object: u64,
    pub surface_generation: u64,
    pub frame: u64,
    pub view_revision: u64,
    pub model_revision: u64,
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub payload_bytes: u32,
    pub mapping_epoch: u64,
    pub protected_scope_nonce: u64,
}
impl Header {
    pub const fn pixel_offset(self) -> usize {
        if matches!(self.producer, Producer::ProtectedRoot) {
            ROOT_PIXEL_OFFSET
        } else {
            APP_PIXEL_OFFSET
        }
    }
    pub const fn backing_pages(self) -> u64 {
        if matches!(self.producer, Producer::ProtectedRoot) {
            super::resources::PROTECTED_PAGES
        } else {
            super::resources::APP_SURFACE_PAGES
        }
    }
    fn valid(self) -> Result<(), Error> {
        if [
            self.process,
            self.thread,
            self.incarnation,
            self.surface_object,
            self.surface_generation,
            self.frame,
            self.view_revision,
            self.model_revision,
            self.mapping_epoch,
        ]
        .into_iter()
        .any(|v| matches!(v, 0 | u64::MAX))
        {
            return Err(Error::Identity);
        }
        let (max_width, max_height) = match self.producer {
            Producer::Application => {
                if !(1..=4).contains(&self.instance) || self.protected_scope_nonce != 0 {
                    return Err(Error::Profile);
                }
                (320, 200)
            }
            Producer::Shell => {
                if self.instance != 0 || self.protected_scope_nonce != 0 {
                    return Err(Error::Profile);
                }
                (640, 200)
            }
            Producer::ProtectedRoot => {
                if self.instance != 0 || self.protected_scope_nonce == u64::MAX {
                    return Err(Error::Profile);
                }
                (640, 80)
            }
        };
        if self.width == 0
            || self.height == 0
            || self.width > max_width
            || self.height > max_height
            || !self.stride_bytes.is_multiple_of(4)
            || self.stride_bytes < self.width.checked_mul(4).ok_or(Error::Layout)?
        {
            return Err(Error::Layout);
        }
        let payload = u64::from(self.stride_bytes)
            .checked_mul(u64::from(self.height))
            .ok_or(Error::Layout)?;
        if payload != u64::from(self.payload_bytes)
            || payload
                .checked_add(self.pixel_offset() as u64)
                .is_none_or(|extent| extent > self.backing_pages() * 4096)
        {
            return Err(Error::Layout);
        }
        Ok(())
    }
    pub fn encode(self) -> Result<[u8; SIZE], Error> {
        self.valid()?;
        let mut b = [0; SIZE];
        b[..8].copy_from_slice(b"EVSURF05");
        b[8..10].copy_from_slice(&5u16.to_le_bytes());
        b[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
        b[12..14].copy_from_slice(&1u16.to_le_bytes());
        b[16] = self.producer as u8;
        b[18..20].copy_from_slice(&self.instance.to_le_bytes());
        for (at, v) in [
            (24, self.process),
            (32, self.thread),
            (40, self.incarnation),
            (48, self.surface_object),
            (56, self.surface_generation),
            (64, self.frame),
            (72, self.view_revision),
            (80, self.model_revision),
            (112, self.mapping_epoch),
            (120, self.protected_scope_nonce),
        ] {
            put(&mut b, at, v);
        }
        for (at, v) in [
            (88, self.width),
            (92, self.height),
            (96, self.stride_bytes),
            (100, self.payload_bytes),
        ] {
            b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[104..106].copy_from_slice(&(self.pixel_offset() as u16).to_le_bytes());
        Ok(b)
    }
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() != SIZE {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVSURF05"
            || b[8..10] != 5u16.to_le_bytes()
            || b[10..12] != (SIZE as u16).to_le_bytes()
            || b[12..14] != 1u16.to_le_bytes()
        {
            return Err(Error::Version);
        }
        if b[14..16]
            .iter()
            .chain(&b[17..18])
            .chain(&b[20..24])
            .chain(&b[106..112])
            .chain(&b[128..])
            .any(|v| *v != 0)
        {
            return Err(Error::Reserved);
        }
        let producer = match b[16] {
            1 => Producer::Application,
            2 => Producer::Shell,
            3 => Producer::ProtectedRoot,
            _ => return Err(Error::Profile),
        };
        let n = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let value = Self {
            producer,
            instance: u16::from_le_bytes(b[18..20].try_into().unwrap()),
            process: word(b, 24),
            thread: word(b, 32),
            incarnation: word(b, 40),
            surface_object: word(b, 48),
            surface_generation: word(b, 56),
            frame: word(b, 64),
            view_revision: word(b, 72),
            model_revision: word(b, 80),
            width: n(88),
            height: n(92),
            stride_bytes: n(96),
            payload_bytes: n(100),
            mapping_epoch: word(b, 112),
            protected_scope_nonce: word(b, 120),
        };
        value.valid()?;
        if usize::from(u16::from_le_bytes(b[104..106].try_into().unwrap())) != value.pixel_offset()
        {
            return Err(Error::Layout);
        }
        Ok(value)
    }
}

/// Root-control registration is meaningful ONLY on Display's separately bound
/// role10 receiver. Its sender capability is never delegated to any child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub sequence: u64,
    pub source_role: super::Role,
    pub producer: Producer,
    pub instance: u16,
    pub process: u64,
    pub thread: u64,
    pub incarnation: u64,
    pub surface_object: u64,
    pub surface_generation: u64,
    pub mapping_epoch: u64,
}
impl Registration {
    pub fn encode(self) -> Result<[u8; 128], Error> {
        if [
            self.sequence,
            self.process,
            self.thread,
            self.incarnation,
            self.surface_object,
            self.surface_generation,
            self.mapping_epoch,
        ]
        .into_iter()
        .any(|v| matches!(v, 0 | u64::MAX))
        {
            return Err(Error::Identity);
        }
        let expected = match self.source_role {
            super::Role::FilesSurface => (Producer::Application, 1),
            super::Role::EditorOneSurface => (Producer::Application, 2),
            super::Role::EditorTwoSurface => (Producer::Application, 3),
            super::Role::InspectorSurface => (Producer::Application, 4),
            super::Role::ShellSurface => (Producer::Shell, 0),
            super::Role::ProtectedSurface => (Producer::ProtectedRoot, 0),
            _ => return Err(Error::Roles),
        };
        if (self.producer, self.instance) != expected {
            return Err(Error::Profile);
        }
        let mut b = [0; 128];
        b[..8].copy_from_slice(b"EVOWNR05");
        b[8] = self.producer as u8;
        b[10..12].copy_from_slice(&self.instance.to_le_bytes());
        for (at, v) in [
            (16, self.sequence),
            (24, self.source_role.selector()),
            (32, self.process),
            (40, self.thread),
            (48, self.incarnation),
            (56, self.surface_object),
            (64, self.surface_generation),
            (72, self.mapping_epoch),
        ] {
            put(&mut b, at, v);
        }
        Ok(b)
    }
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 128 {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVOWNR05" {
            return Err(Error::Version);
        }
        let producer = match b[8] {
            1 => Producer::Application,
            2 => Producer::Shell,
            3 => Producer::ProtectedRoot,
            _ => return Err(Error::Profile),
        };
        let value = Self {
            sequence: word(b, 16),
            source_role: super::Role::from_selector(word(b, 24)).ok_or(Error::Roles)?,
            producer,
            instance: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            process: word(b, 32),
            thread: word(b, 40),
            incarnation: word(b, 48),
            surface_object: word(b, 56),
            surface_generation: word(b, 64),
            mapping_epoch: word(b, 72),
        };
        if value.encode()?.as_slice() != b {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
    /// Pure comparison after actual root-only registration/source resolution.
    /// Process/thread come from ServingOrigin; incarnation must be resolved
    /// from that actual admitted actor (Root's factory context if its registry
    /// field is0). Logical source IDs come from Root-only registration. Actual
    /// MemoryObject/mapping authority is verified independently by Kernel.
    pub fn matches(
        self,
        h: Header,
        caller_process: u64,
        caller_thread: u64,
        caller_incarnation: u64,
    ) -> bool {
        self.process == caller_process
            && self.thread == caller_thread
            && self.incarnation == caller_incarnation
            && (
                self.producer,
                self.instance,
                self.process,
                self.thread,
                self.incarnation,
                self.surface_object,
                self.surface_generation,
                self.mapping_epoch,
            ) == (
                h.producer,
                h.instance,
                h.process,
                h.thread,
                h.incarnation,
                h.surface_object,
                h.surface_generation,
                h.mapping_epoch,
            )
    }
}
