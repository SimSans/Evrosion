use super::*;
use std::{cell::RefCell, rc::Rc, vec::Vec};

struct State {
    calls: Vec<(Request, u64)>,
    loads: usize,
    stores: usize,
    reply: Option<[u8; 8]>,
    fail: bool,
    child: Option<u64>,
    session: bool,
}
#[derive(Clone)]
struct Model(Rc<RefCell<State>>);
impl Wire for Model {
    type Error = u8;
    fn supports_session(&self) -> bool {
        self.0.borrow().session
    }
    fn capture_session_deadline(&self, _: u64) -> Option<u64> {
        self.0.borrow().child
    }
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], u8> {
        let request = Request::decode(&bytes).unwrap();
        let mut state = self.0.borrow_mut();
        state.calls.push((request, deadline));
        if state.fail {
            Err(3)
        } else {
            Ok(state.reply.unwrap_or_else(|| request.success().encode()))
        }
    }
}
impl Window for Model {
    fn load(&self, out: &mut Sector) {
        self.0.borrow_mut().loads += 1;
        out.fill(0x5a);
    }
    fn store(&self, _: &Sector) {
        self.0.borrow_mut().stores += 1;
    }
}
fn setup() -> (Device<Model, Model>, Model) {
    let model = Model(Rc::new(RefCell::new(State {
        calls: Vec::new(),
        loads: 0,
        stores: 0,
        reply: None,
        fail: false,
        child: Some(100),
        session: true,
    })));
    (Device::new(model.clone(), model.clone()).unwrap(), model)
}

#[test]
fn native_backend_reads_only_closed_original_ranges_and_never_publishes_mutators() {
    let (mut device, model) = setup();
    for lba in [0, 13, 16, 29] {
        let mut out = [0; 512];
        device.read(lba, &mut out, 200).unwrap();
        assert_eq!(out, [0x5a; 512]);
    }
    let calls = model.0.borrow().calls.clone();
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|(_, deadline)| *deadline == 100));
    for lba in [14, 15, 30, 32, u32::MAX as u64, u64::MAX] {
        assert_eq!(device.read(lba, &mut [0; 512], 200), Err(Error::Bounds));
    }
    assert_eq!(device.write(0, &[7; 512], 200), Err(Error::ReadOnly));
    assert_eq!(device.flush(200), Err(Error::ReadOnly));
    let state = model.0.borrow();
    assert_eq!(state.calls, calls);
    assert_eq!(state.loads, 4);
    assert_eq!(state.stores, 0);
}

#[test]
fn wrong_reply_decode_or_transport_never_reads_window_and_poison_blocks_followup_region() {
    for mode in 0..3 {
        let (mut device, model) = setup();
        match mode {
            0 => model.0.borrow_mut().reply = Some(Request::Read { sector: 1 }.success().encode()),
            1 => model.0.borrow_mut().reply = Some([0; 8]),
            _ => model.0.borrow_mut().fail = true,
        }
        let mut out = [0xa5; 512];
        assert!(device.read(0, &mut out, 200).is_err());
        assert_eq!(out, [0xa5; 512]);
        assert!(device.is_poisoned());
        assert_eq!(device.read(16, &mut out, 200), Err(Error::NeedsRecovery));
        let state = model.0.borrow();
        assert_eq!(state.calls.len(), 1);
        assert_eq!(state.loads, 0);
        assert_eq!(state.stores, 0);
    }
}

#[test]
fn expired_invalid_or_extended_child_deadline_refuses_before_ipc_and_window() {
    let (mut device, model) = setup();
    for child in [None, Some(0), Some(201), Some(u64::MAX)] {
        model.0.borrow_mut().child = child;
        assert_eq!(device.read(0, &mut [0; 512], 200), Err(Error::Deadline));
    }
    assert!(model.0.borrow().calls.is_empty());
    assert_eq!(model.0.borrow().loads, 0);
    assert_eq!(model.0.borrow().stores, 0);
    assert!(!device.is_poisoned());
    model.0.borrow_mut().session = false;
    assert!(Device::new(model.clone(), model.clone()).is_none());
}
