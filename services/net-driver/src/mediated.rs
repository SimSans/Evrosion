//! Scoped scalar byte PIO and separately negotiated fixed Byte4 groups execute I/O.
use crate::device::Ports;
use ev_userspace_runtime as rt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Handle,
    Port,
    Denied(u64),
    Reply,
}

pub struct Mediated {
    capability: u64,
}

impl Mediated {
    /// The caller obtains the actual handle from its checked readonly startup.
    /// The Kernel independently checks kind/rights/lineage/range on every call.
    pub fn new(capability: u64) -> Result<Self, Error> {
        if capability == 0 {
            return Err(Error::Handle);
        }
        // An older kernel is refused before the first physical port operation.
        byte_batch_info_reply(rt::call4(rt::syscall::PORT_BYTE_BATCH_INFO, 0, 0, 0, 0))?;
        Ok(Self { capability })
    }

    fn port(port: u16) -> Result<(), Error> {
        if !(ev_net_device::ne2000::IO_BASE
            ..ev_net_device::ne2000::IO_BASE + ev_net_device::ne2000::IO_BYTES)
            .contains(&port)
        {
            return Err(Error::Port);
        }
        Ok(())
    }
}

pub fn byte_batch_info_reply(reply: rt::CapReply) -> Result<(), Error> {
    if reply.status != 0
        || reply.value != rt::syscall::PORT_BYTE_BATCH_V1
        || reply.capability != 0
        || reply.serial != 0
    {
        return Err(Error::Reply);
    }
    Ok(())
}
pub fn input_bytes4_reply(reply: rt::CapReply) -> Result<u32, Error> {
    if reply.status != 0 {
        if reply.value != 0 || reply.capability != 0 || reply.serial != 0 {
            return Err(Error::Reply);
        }
        return Err(Error::Denied(reply.status));
    }
    if reply.value > u32::MAX as u64 || reply.capability != 0 || reply.serial != 0 {
        return Err(Error::Reply);
    }
    Ok(reply.value as u32)
}
pub fn input_reply(reply: rt::CapReply) -> Result<u8, Error> {
    if reply.status != 0 {
        if reply.value != 0 || reply.capability != 0 || reply.serial != 0 {
            return Err(Error::Reply);
        }
        return Err(Error::Denied(reply.status));
    }
    if reply.capability != 0 || reply.serial != 0 || reply.value > 255 {
        return Err(Error::Reply);
    }
    Ok(reply.value as u8)
}

pub fn output_reply(reply: rt::CapReply) -> Result<(), Error> {
    if reply.status != 0 {
        if reply.value != 0 || reply.capability != 0 || reply.serial != 0 {
            return Err(Error::Reply);
        }
        return Err(Error::Denied(reply.status));
    }
    if reply.capability != 0 || reply.serial != 0 || reply.value != 0 {
        return Err(Error::Reply);
    }
    Ok(())
}

impl Ports for Mediated {
    type Error = Error;

    #[inline]
    fn may_reuse_byte4_clock(&self) -> bool {
        // new() already negotiated the same actual Core's Byte4 contract.
        // MONOTONIC and the per-trap Byte4 cut use its nondecreasing timer.
        true
    }

    fn input_bytes4(&mut self, port: u16, deadline: u64) -> Result<u32, Error> {
        Self::port(port)?;
        input_bytes4_reply(rt::call4(
            rt::syscall::PORT_INPUT_BYTES4,
            self.capability,
            u64::from(port),
            deadline,
            0,
        ))
    }
    fn output_bytes4(&mut self, port: u16, value: u32, deadline: u64) -> Result<(), Error> {
        Self::port(port)?;
        output_reply(rt::call4(
            rt::syscall::PORT_OUTPUT_BYTES4,
            self.capability,
            u64::from(port),
            deadline,
            u64::from(value),
        ))
    }
    fn input(&mut self, port: u16) -> Result<u8, Error> {
        Self::port(port)?;
        input_reply(rt::call4(
            rt::syscall::PORT_INPUT,
            self.capability,
            u64::from(port),
            1,
            0,
        ))
    }

    fn output(&mut self, port: u16, value: u8) -> Result<(), Error> {
        Self::port(port)?;
        output_reply(rt::call4(
            rt::syscall::PORT_OUTPUT,
            self.capability,
            u64::from(port),
            1,
            u64::from(value),
        ))
    }

    fn now(&mut self) -> Result<u64, Error> {
        let reply = rt::call4(rt::syscall::MONOTONIC, 0, 0, 0, 0);
        if reply.status != 0 {
            return Err(Error::Denied(reply.status));
        }
        if reply.capability != 0 || reply.serial != 0 || reply.value == u64::MAX {
            return Err(Error::Reply);
        }
        Ok(reply.value)
    }

    fn yield_now(&mut self) -> Result<(), Error> {
        output_reply(rt::call4(rt::syscall::YIELD, 0, 0, 0, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_batch_requires_exact_negotiation_and_zero_extended_outputs() {
        let info = rt::CapReply {
            status: 0,
            value: rt::syscall::PORT_BYTE_BATCH_V1,
            capability: 0,
            serial: 0,
        };
        assert_eq!(byte_batch_info_reply(info), Ok(()));
        for bad in [
            rt::CapReply { status: 1, ..info },
            rt::CapReply {
                value: rt::syscall::PORT_BATCH_V1,
                ..info
            },
            rt::CapReply {
                capability: 1,
                ..info
            },
            rt::CapReply { serial: 1, ..info },
        ] {
            assert_eq!(byte_batch_info_reply(bad), Err(Error::Reply));
        }
        let ok = rt::CapReply {
            value: 0x04030201,
            ..info
        };
        assert_eq!(input_bytes4_reply(ok), Ok(0x04030201));
        assert_eq!(
            input_bytes4_reply(rt::CapReply {
                value: u32::MAX as u64,
                ..ok
            }),
            Ok(u32::MAX)
        );
        for bad in [
            rt::CapReply {
                value: 1 << 32,
                ..ok
            },
            rt::CapReply {
                capability: 1,
                ..ok
            },
            rt::CapReply { serial: 1, ..ok },
            rt::CapReply { status: 4, ..ok },
        ] {
            assert_eq!(input_bytes4_reply(bad), Err(Error::Reply));
        }
        assert_eq!(
            input_bytes4_reply(rt::CapReply {
                status: 4,
                value: 0,
                ..ok
            }),
            Err(Error::Denied(4))
        );
    }
    #[test]
    fn only_canonical_byte_and_zero_output_replies_are_accepted() {
        let zero = rt::CapReply {
            status: 0,
            value: 0,
            capability: 0,
            serial: 0,
        };
        assert_eq!(input_reply(rt::CapReply { value: 255, ..zero }), Ok(255));
        assert_eq!(output_reply(zero), Ok(()));
        for bad in [
            rt::CapReply { value: 256, ..zero },
            rt::CapReply {
                capability: 1,
                ..zero
            },
            rt::CapReply { serial: 1, ..zero },
        ] {
            assert_eq!(input_reply(bad), Err(Error::Reply));
            assert_eq!(output_reply(bad), Err(Error::Reply));
        }
        assert_eq!(
            output_reply(rt::CapReply { value: 1, ..zero }),
            Err(Error::Reply)
        );
        assert_eq!(
            input_reply(rt::CapReply { status: 1, ..zero }),
            Err(Error::Denied(1))
        );
        assert_eq!(
            output_reply(rt::CapReply {
                status: 1,
                capability: 1,
                ..zero
            }),
            Err(Error::Reply)
        );
    }

    #[test]
    fn local_port_filter_never_truncates_or_widens_the_device_extent() {
        assert!(Mediated::new(0).is_err());
        for port in [0, 0x60, 0x64, 0x2ff, 0x320, 0x3f8, u16::MAX] {
            assert_eq!(Mediated::port(port), Err(Error::Port));
        }
        for port in 0x300..0x320 {
            assert_eq!(Mediated::port(port), Ok(()));
        }
    }
}
