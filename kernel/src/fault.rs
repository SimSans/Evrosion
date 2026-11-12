//! Fixed scalar diagnostics. Identities describe a fault; they grant no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub process: u64,
    pub thread: u64,
    pub vector: u64,
    pub error: u64,
    pub address: u64,
    pub instruction: u64,
}
impl Record {
    /// Scalar presentation of an actual captured user frame. The caller must
    /// separately authorize the real process owner; this function is no lookup
    /// or permission receipt. An unrelated/kernel/nonfault frame is rejected.
    pub fn context_field(
        self,
        job: crate::scheduler::JobId,
        context: &crate::user_context::UserContext,
        field: u64,
    ) -> Option<u64> {
        if self.process == 0
            || self.thread == 0
            || !context.ordinary_user_fault()
            || (self.vector, self.error, self.instruction)
                != (context.vector, context.error, context.rip)
        {
            return None;
        }
        Some(match field {
            0 => job.diagnostic_id(),
            1 => self.process,
            2 => self.thread,
            3 => self.vector,
            4 => self.error,
            5 => self.address,
            6 => self.instruction,
            7 => context.rsp,
            8 => context.flags,
            9..=23 => context.registers[(field - 9) as usize],
            _ => return None,
        })
    }
    pub fn encode(self) -> [u8; 48] {
        let mut bytes = [0; 48];
        for (slot, value) in bytes.as_chunks_mut::<8>().0.iter_mut().zip([
            self.process,
            self.thread,
            self.vector,
            self.error,
            self.address,
            self.instruction,
        ]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut words = [0; 6];
        for (word, value) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
            *word = u64::from_le_bytes(*value);
        }
        if words[0] == 0
            || words[1] == 0
            || !matches!(
                words[2],
                0 | 1 | 3 | 4 | 5 | 6 | 7 | 10 | 11 | 12 | 13 | 14 | 16 | 17 | 19
            )
        {
            return None;
        }
        Some(Self {
            process: words[0],
            thread: words[1],
            vector: words[2],
            error: words[3],
            address: words[4],
            instruction: words[5],
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capability::{Authority, Kind, Rights},
        ipc::{Error, Mailbox, Outgoing},
        time::Deadline,
    };
    #[test]
    fn scalar_context_preserves_every_register_and_rejects_an_unrelated_frame() {
        use crate::{scheduler::Scheduler, user_context::UserContext};
        let job = Scheduler::new().create_job().unwrap();
        let mut frame = UserContext::new(0x1000, 0x8000).unwrap();
        frame.vector = 14;
        frame.error = 4;
        frame.registers = core::array::from_fn(|i| 0x1234_5670 + i as u64);
        let record = Record {
            process: 2,
            thread: 3,
            vector: 14,
            error: 4,
            address: 0xdead_beef,
            instruction: 0x1000,
        };
        let mut expected = [0; 24];
        expected[..9].copy_from_slice(&[
            job.diagnostic_id(),
            2,
            3,
            14,
            4,
            0xdead_beef,
            0x1000,
            0x8000,
            0x202,
        ]);
        expected[9..].copy_from_slice(&frame.registers);
        for (field, value) in expected.into_iter().enumerate() {
            assert_eq!(record.context_field(job, &frame, field as u64), Some(value));
        }
        assert_eq!(record.context_field(job, &frame, 24), None);
        assert_eq!(record.context_field(job, &frame, u64::MAX), None);
        for change in 0..4 {
            let mut other = frame;
            match change {
                0 => other.cs = 0,
                1 => other.vector = 6,
                2 => other.error = 5,
                _ => other.rip += 1,
            }
            assert_eq!(record.context_field(job, &other, 6), None);
        }
    }
    #[test]
    fn bounded_fault_channel_preserves_authority_and_overflow_order() {
        let mut a = Authority::new();
        let observer = a.create_space().unwrap();
        let kernel = a.create_space().unwrap();
        let attacker = a.create_space().unwrap();
        let send = a
            .create_root(
                kernel,
                Kind::Endpoint,
                Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::SEND
                    | Rights::TRANSFER,
            )
            .unwrap();
        let receive = a
            .derive(kernel, send, observer, Rights::RECEIVE | Rights::CONTROL)
            .unwrap();
        let mut queue = Mailbox::new(&mut a, observer, receive).unwrap();
        let record = Record {
            process: 2,
            thread: 2,
            vector: 14,
            error: 4,
            address: 0,
            instruction: 4096,
        };
        let bytes = record.encode();
        assert_eq!(Record::decode(&bytes), Some(record));
        for len in 0..48 {
            assert_eq!(Record::decode(&bytes[..len]), None);
        }
        let mut malformed = bytes;
        malformed[16] = 18;
        assert_eq!(Record::decode(&malformed), None);
        let outgoing = || Outgoing {
            bytes: &bytes,
            capability: None,
            deadline: Deadline::after(0, 10).unwrap(),
        };
        assert!(queue.send(&mut a, attacker, send, outgoing(), 0).is_err());
        for _ in 0..4 {
            queue.send(&mut a, kernel, send, outgoing(), 0).unwrap();
        }
        assert_eq!(
            queue.send(&mut a, kernel, send, outgoing(), 0),
            Err(Error::Full)
        );
        assert!(queue.receive(&mut a, attacker, receive, 0).is_err());
        for _ in 0..4 {
            let delivered = queue.receive(&mut a, observer, receive, 0).unwrap();
            assert_eq!(
                Record::decode(&delivered.bytes[..delivered.length]),
                Some(record)
            );
        }
        assert_eq!(
            queue.receive(&mut a, observer, receive, 0),
            Err(Error::Empty)
        );
        let pending = queue.send(&mut a, kernel, send, outgoing(), 0).unwrap();
        queue.receiver_died(observer).unwrap();
        assert_eq!(
            queue.reclaim(&mut a, kernel, pending, 0),
            Ok(crate::ipc::Reclaimed::NoCapability)
        );
        queue.retire_empty(&mut a).unwrap();
        assert_eq!(
            queue.send(&mut a, kernel, send, outgoing(), 0),
            Err(Error::Closed)
        );
    }
}
