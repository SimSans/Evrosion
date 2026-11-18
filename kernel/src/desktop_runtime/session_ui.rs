//! Diagnostic-only scalar recognizers; no focus, approval, storage or authority
//! decision is made here. Actual protected endpoints/senders are joined by the
//! runtime before these fields are observed. Hosted tests compare real codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Barrier {
    pub frame: u32,
    pub sequence: u32,
    pub flags: u8,
    pub buttons: u8,
}
pub(crate) fn barrier(request: u64, reply: u64) -> Option<Barrier> {
    let request = request.to_le_bytes();
    let reply = reply.to_le_bytes();
    let frame = u32::from_le_bytes(request[4..].try_into().unwrap());
    let sequence = u32::from_le_bytes(reply[4..].try_into().unwrap());
    (&request[..4] == b"KBR2"
        && reply[..2] == [b'B', 2]
        && frame != u32::MAX
        && sequence != u32::MAX
        && reply[2] & !15 == 0
        && reply[3] & !63 == 0)
        .then_some(Barrier {
            frame,
            sequence,
            flags: reply[2],
            buttons: reply[3],
        })
}
pub(crate) struct BarrierSample {
    pub fields: Barrier,
    /// Sampling bounds serial history, never the actual retained barrier.
    pub sample: Option<u64>,
}
/// Pure join of facts supplied by the actual protected runtime. These numeric
/// identities grant no authority; the caller still verifies route/actor roles
/// and retains its typed actual ProcessId in the resulting runtime barrier.
pub(crate) fn barrier_at_present(
    request: u64,
    reply: u64,
    caller_process: u64,
    presented_process: u64,
    presented_frame: u64,
    counter: &mut u64,
) -> Option<BarrierSample> {
    let fields = barrier(request, reply)?;
    if caller_process == 0
        || caller_process != presented_process
        || u64::from(fields.frame) != presented_frame
    {
        return None;
    }
    Some(BarrierSample {
        fields,
        sample: sample(counter),
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub x: u16,
    pub y: u8,
    pub sequence: u32,
}
pub(crate) fn cursor(request: u64, reply: u64) -> Option<Cursor> {
    let request = request.to_le_bytes();
    let reply = reply.to_le_bytes();
    let x = u16::from(request[2]) | u16::from((request[1] >> 2) & 1) << 8;
    let sequence = u32::from_le_bytes(request[4..].try_into().unwrap());
    (request[0] == b'C'
        && request[1] & !4 == 1
        && reply[0] == b'C'
        && reply[1] == ((request[1] & 4) | 2)
        && request[2..] == reply[2..]
        && x < 320
        && request[3] < 200
        && sequence != 0
        && sequence != u32::MAX)
        .then_some(Cursor {
            x,
            y: request[3],
            sequence,
        })
}
/// Increment actual cumulative observations even after the finite sample ends.
/// Exhaustion fails closed; counters never wrap or restart sampling.
pub(crate) fn sample(counter: &mut u64) -> Option<u64> {
    *counter = counter
        .checked_add(1)
        .expect("session UI cumulative counter exhausted");
    (*counter <= 32).then_some(*counter)
}
