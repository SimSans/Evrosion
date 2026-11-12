//! Ordinary scalar boundary derives actual identity/domain from dispatch.
use super::*;
impl Runtime<'_, '_> {
    pub(super) fn syscall(
        &mut self,
        index: usize,
        frame: &mut UserContext,
        frames: &mut BootstrapFrames,
    ) -> bool {
        let m = self.current(index);
        match decode(frame) {
            Ok(Call::Yield) => scalar(frame, 0, 0),
            Ok(Call::Monotonic) => scalar(frame, 0, crate::timer::now()),
            Ok(Call::Inspect { capability, rights }) => {
                let allowed = [Kind::Memory, Kind::Endpoint, Kind::Job, Kind::Process]
                    .into_iter()
                    .any(|kind| self.a.authorize(m.domain, capability, kind, rights).is_ok());
                scalar(frame, u64::from(!allowed), 0);
            }
            Ok(Call::CreateJob { creator, template }) if index == 0 => {
                if let Some(slot) = self.jobs.iter().position(Option::is_none) {
                    match self
                        .registry
                        .create_job(self.a, self.s, m.domain, creator, template)
                    {
                        Ok(cap) => {
                            self.jobs[slot] =
                                Some(self.registry.job_id(self.a, m.domain, cap).unwrap());
                            scalar(frame, 0, cap.0);
                        }
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 2, 0)
                }
            }
            Ok(Call::CreateProcess { job, image }) if index == 0 => {
                match self.create_process(m.domain, job, image) {
                    Ok(cap) => scalar(frame, 0, cap.0),
                    Err(code) => scalar(frame, code, 0),
                }
            }
            Ok(Call::Delegate {
                process,
                source,
                selector,
            }) if index == 0 => scalar(
                frame,
                u64::from(
                    self.registry
                        .delegate(self.a, m.domain, process, source, selector)
                        .is_err(),
                ),
                0,
            ),
            Ok(Call::CreateEndpoint(job)) if index == 0 => {
                if let Some(slot) = self.wires[..3].iter().position(Option::is_none) {
                    match self.registry.create_channel(self.a, m.domain, job) {
                        Ok((cap, mailbox)) => {
                            let object = self
                                .a
                                .authorize(m.domain, cap, Kind::Endpoint, Rights::CONTROL)
                                .unwrap()
                                .identity();
                            self.wires[slot] = Some(Wire::new(object, m.domain, mailbox));
                            scalar(frame, 0, cap.0)
                        }
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 2, 0)
                }
            }
            Ok(Call::BindReceiver { endpoint, process }) => {
                let result = self.bind(index, endpoint, process);
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Start(cap)) if index == 0 => {
                let result = self.start(m.domain, cap, frames);
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::ProcessIdentity(cap)) if index == 0 => {
                match self.find_control(m.domain, cap) {
                    Ok(target) => {
                        let target = self.current(target);
                        abi::process_identity(
                            frame,
                            target.process.diagnostic_id(),
                            target.thread.diagnostic_id(),
                        );
                    }
                    Err(code) => scalar(frame, code, 0),
                }
            }
            Ok(Call::Observe(cap)) => match self.registry.observe(self.a, self.s, m.domain, cap) {
                Ok(stopped) => scalar(frame, 0, u64::from(stopped)),
                Err(_) => scalar(frame, 1, 0),
            },
            Ok(Call::StopProcess(cap)) if index == 0 => {
                let result = self
                    .find_control(m.domain, cap)
                    .and_then(|target| self.stop_actor(target, true));
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Reap(cap)) if index == 0 => {
                let result = self.find_control(m.domain, cap).and_then(|target| {
                    // SAFETY: actual stopped/settled gates in reap preserve owners on refusal.
                    unsafe { self.reap(target, frames) }
                });
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Close(cap)) => {
                let result = self.a.close(m.domain, cap);
                self.collect();
                scalar(frame, u64::from(result.is_err()), 0);
            }
            Ok(Call::Send {
                endpoint,
                value,
                capability: None,
            }) => {
                let result = self
                    .wire(m, endpoint, Rights::SEND)
                    .ok_or(IpcError::WrongOwner)
                    .and_then(|wire| {
                        self.wires[wire].as_mut().unwrap().send(
                            self.a,
                            m,
                            endpoint,
                            value,
                            self.stop,
                            crate::timer::now(),
                        )
                    });
                match result {
                    Ok(_) => scalar(frame, 0, 0),
                    Err(IpcError::Full) => scalar(frame, 2, 0),
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::Receive(cap) | Call::ReceiveEvent(cap)) => {
                let event = matches!(decode(frame), Ok(Call::ReceiveEvent(_)));
                if let Some(wire) = self.wire(m, cap, RECEIVE) {
                    match self.wires[wire].as_mut().unwrap().receive(
                        self.a,
                        m.domain,
                        cap,
                        crate::timer::now(),
                    ) {
                        Ok((delivery, process, thread)) => {
                            assert_eq!(delivery.capability, None);
                            assert_eq!(delivery.length, 8);
                            let value = u64::from_le_bytes(delivery.bytes[..8].try_into().unwrap());
                            if event {
                                abi::event(
                                    frame,
                                    value,
                                    process.diagnostic_id(),
                                    thread.diagnostic_id(),
                                );
                            } else {
                                scalar(frame, 0, value);
                            }
                        }
                        Err(IpcError::Empty) => abi::receive_error(frame, event, 2),
                        Err(_) => abi::receive_error(frame, event, 1),
                    }
                } else {
                    abi::receive_error(frame, event, 1)
                }
            }
            Ok(Call::Rpc {
                endpoint,
                value,
                deadline,
            }) => return self.call(index, endpoint, value, deadline, frame),
            Ok(Call::ReceiveRpc(cap)) => self.receive_rpc(index, cap, frame),
            Ok(Call::ReplyRpc {
                endpoint,
                value,
                serial,
            }) => self.reply_rpc(index, endpoint, value, serial, frame),
            Ok(Call::RpcDeadline) => {
                let deadline = self
                    .rpc
                    .serving(m.thread)
                    .and_then(|id| self.rpc.context(id).ok())
                    .map(|c| c.deadline.tick());
                scalar(
                    frame,
                    if deadline.is_some() { 0 } else { 1 },
                    deadline.unwrap_or(0),
                );
            }
            Ok(Call::Exit(code)) => {
                self.observe_life(index, LifeKind::Exit, Some(code));
                self.facts.exits += 1;
                assert_eq!(self.s.exit(0), Ok(m.thread));
                assert_eq!(code, 0, "provider actor actual nonzero Exit");
                if index == 0 {
                    assert_eq!(self.rpc.outstanding(), 0);
                    assert!(self.pending.is_none());
                    assert!(self.actors.iter().all(Option::is_none));
                    self.facts.root_exit = Some(code);
                    self.root_exited = true;
                } else {
                    assert_eq!(
                        self.actors[index - 1].as_ref().unwrap().kind,
                        ActorKind::Consumer,
                        "provider cannot voluntarily Exit"
                    );
                    self.facts.consumer_exit = Some(code);
                    self.stop_actor(index, false).unwrap();
                }
                return true;
            }
            _ => scalar(frame, 1, 0),
        }
        false
    }
}
