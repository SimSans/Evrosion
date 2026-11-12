//! Scalar boundary derives every domain and identity from actual dispatch.
use super::*;
impl Runtime<'_, '_> {
    pub(super) fn syscall(
        &mut self,
        index: usize,
        frame: &mut UserContext,
        frames: &mut BootstrapFrames,
    ) -> bool {
        let m = self.current(index);
        #[cfg(feature = "test-m5-native")]
        if let Some(native) = &mut self.native {
            native.last_syscall[index] = Some(frame.registers[14]);
        }
        let now = crate::timer::now();
        if frame.registers[14] == 41 {
            self.grant_selected(index, frame);
            return false;
        }
        match decode(frame) {
            #[cfg(feature = "test-m5-native")]
            Ok(Call::EnqueueManagedRead {
                process,
                source,
                inbox,
                nonce,
            }) => self.grant_managed(index, process, source, inbox, nonce, frame),
            #[cfg(feature = "test-m5-native")]
            Ok(Call::InhibitManagedProcess(cap)) => match self.inhibit_managed(index, cap) {
                Ok(()) => scalar(frame, 0, 0),
                Err(reason) => scalar(frame, reason, 0),
            },
            Ok(Call::Yield) => scalar(frame, 0, 0),
            Ok(Call::Monotonic) => scalar(frame, 0, now),
            Ok(Call::JobInfo { capability, field }) => {
                let result = ev_kernel::job_info::inspect(
                    self.a,
                    self.s,
                    self.registry,
                    m,
                    capability,
                    field,
                );
                #[cfg(feature = "test-m5-native")]
                if index == 0 {
                    let (status, value, denial) = match result {
                        Ok(value) => (0, value, 0),
                        Err(ev_kernel::job_info::Error::Service(
                            ev_kernel::service::Error::Authority(
                                ev_kernel::capability::Error::WrongKind,
                            ),
                        )) => (1, 0, 1),
                        Err(ev_kernel::job_info::Error::Service(
                            ev_kernel::service::Error::Authority(
                                ev_kernel::capability::Error::InvalidHandle
                                | ev_kernel::capability::Error::Revoked
                                | ev_kernel::capability::Error::DeadObject,
                            ),
                        )) => (1, 0, 2),
                        Err(_) => (1, 0, 3),
                    };
                    let native = self.native.as_mut().unwrap();
                    native.diagnostic_queries = native
                        .diagnostic_queries
                        .checked_add(1)
                        .expect("bounded diagnostic sequence");
                    assert!(
                        native.diagnostic_queries <= 512,
                        "Native actual Job query evidence budget exhausted"
                    );
                    (self.observations)(Observation::NativeJobField(NativeJobField {
                        sequence: native.diagnostic_queries,
                        root_process: m.process.diagnostic_id(),
                        root_thread: m.thread.diagnostic_id(),
                        capability: capability.0,
                        field,
                        value,
                        tick: now,
                        status,
                        denial,
                    }));
                }
                match result {
                    Ok(value) => {
                        scalar(frame, 0, value);
                    }
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::FaultInfo { capability, field }) => {
                let result = self.find_control(m.domain, capability).and_then(|target| {
                    let actor = self.actors[target - 1].as_ref().unwrap();
                    let record = actor.fault.ok_or(2u64)?;
                    if self.s.state(actor.meta.thread) != Ok(State::Exited)
                        || self.s.thread_process(actor.meta.thread) != Ok(actor.meta.process)
                        || self.s.process_job(actor.meta.process) != Ok(actor.meta.job)
                        || record.process != actor.meta.process.diagnostic_id()
                        || record.thread != actor.meta.thread.diagnostic_id()
                    {
                        return Err(1);
                    }
                    record
                        .context_field(actor.meta.job, &actor.context, field)
                        .ok_or(1)
                });
                match result {
                    Ok(value) => scalar(frame, 0, value),
                    Err(reason) => scalar(frame, reason, 0),
                }
            }
            Ok(Call::Inspect { capability, rights }) => {
                let allowed = [
                    Kind::Memory,
                    Kind::Endpoint,
                    Kind::Process,
                    Kind::Thread,
                    Kind::Job,
                    Kind::Mutex,
                    Kind::IoPorts,
                    Kind::Display,
                ]
                .into_iter()
                .any(|k| self.a.authorize(m.domain, capability, k, rights).is_ok());
                scalar(frame, u64::from(!allowed), 0);
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
                let value = self
                    .rpc
                    .serving(m.thread)
                    .and_then(|id| self.rpc.context(id).ok())
                    .map(|c| c.deadline.tick());
                scalar(
                    frame,
                    if value.is_some() { 0 } else { 1 },
                    value.unwrap_or(0),
                );
            }
            Ok(Call::CreateJob { creator, template }) if index == 0 => {
                if let Some(slot) = self.jobs.iter().position(Option::is_none) {
                    match self
                        .registry
                        .create_job(self.a, self.s, m.domain, creator, template)
                    {
                        Ok(h) => {
                            self.jobs[slot] =
                                Some(self.registry.job_id(self.a, m.domain, h).unwrap());
                            scalar(frame, 0, h.0);
                        }
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 2, 0)
                }
            }
            Ok(Call::CreateProcess { job, image }) if index == 0 => {
                match self.create_process(m.domain, job, image) {
                    Ok(h) => scalar(frame, 0, h.0),
                    Err(e) => scalar(frame, e, 0),
                }
            }
            Ok(Call::Delegate {
                process,
                source,
                selector,
            }) if index == 0 => {
                let valid = self
                    .find_control(m.domain, process)
                    .ok()
                    .and_then(|i| {
                        let child = self.actors[i - 1].as_ref().unwrap().child;
                        let grant =
                            *root_v2::graph::grants(child).get(selector.checked_sub(1)? as usize)?;
                        let actual = self
                            .a
                            .authorize(
                                m.domain,
                                source,
                                kind(grant.kind),
                                Rights::from_bits(grant.rights).unwrap(),
                            )
                            .ok()?
                            .identity();
                        let expected = match grant.source {
                            root_v2::graph::Source::Root(role) => {
                                self.source_identity(role.selector() as usize - 1, kind(grant.kind))
                            }
                            root_v2::graph::Source::Endpoint(channel) => {
                                self.wires[channel.index()].as_ref()?.object
                            }
                        };
                        Some(actual == expected)
                    })
                    .unwrap_or(false);
                if valid {
                    match self
                        .registry
                        .delegate(self.a, m.domain, process, source, selector)
                    {
                        Ok(h) => scalar(frame, 0, h.0),
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 1, 0)
                }
            }
            Ok(Call::Start(cap)) if index == 0 => {
                // SAFETY: actual RootCONTROL resolves an exact held registry
                // target; this controller owns all physical image slots/frames.
                let result = unsafe { self.start(m.domain, cap, frames) };
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::CreateEndpoint(job)) if index == 0 => {
                let slot = self.wires[..15].iter().position(Option::is_none);
                if let Some(slot) = slot {
                    match if let Some(receipt) = self.receipts[0].take() {
                        match self
                            .registry
                            .create_channel_reusing(self.a, m.domain, job, receipt)
                        {
                            Ok(value) => Ok(value),
                            Err(rejected) => {
                                self.receipts[0] = Some(rejected.receipt);
                                Err(rejected.error)
                            }
                        }
                    } else {
                        self.registry.create_channel(self.a, m.domain, job)
                    } {
                        Ok((cap, mailbox)) => {
                            let object = self
                                .a
                                .authorize(m.domain, cap, Kind::Endpoint, Rights::CONTROL)
                                .unwrap()
                                .identity();
                            self.wires[slot] = Some(Wire::new(object, m.domain, mailbox));
                            scalar(frame, 0, cap.0);
                        }
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 2, 0)
                }
            }
            Ok(Call::BindReceiver { endpoint, process }) => {
                self.bind_receiver(index, endpoint, process, frame)
            }
            Ok(Call::Send {
                endpoint,
                value,
                capability: None,
            }) => {
                let wire = self.wire(m, endpoint, Rights::SEND);
                let result = wire
                    .filter(|&w| matches!(w, 4 | 6 | 7 | 15))
                    .ok_or(IpcError::WrongOwner)
                    .and_then(|w| {
                        self.wires[w]
                            .as_mut()
                            .unwrap()
                            .send(self.a, m, endpoint, value, self.stop, now)
                    });
                match result {
                    Ok(_ticket) => {
                        self.accepted_event(index, wire.unwrap(), value);
                        scalar(frame, 0, 0);
                    }
                    Err(IpcError::Full) => scalar(frame, 2, 0),
                    Err(IpcError::Closed)
                        if index == Child::Input.index() + 1
                            && wire == Some(Channel::InputKeys.index()) =>
                    {
                        scalar(frame, 2, 0)
                    }
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::Receive(cap) | Call::ReceiveEvent(cap)) => {
                if index == Child::App.index() + 1
                    && self.wire(m, cap, RECEIVE) == Some(Channel::GrantInbox.index())
                    && matches!(decode(frame), Ok(Call::Receive(_)))
                {
                    self.receive_grant(index, frame);
                    return false;
                }

                let event = matches!(decode(frame), Ok(Call::ReceiveEvent(_)));
                if let Some(w) = self.wire(m, cap, RECEIVE) {
                    match self.wires[w].as_mut().unwrap().receive(self.a, m, cap, now) {
                        Ok((d, p, t)) => {
                            self.received_event(
                                index,
                                w,
                                p,
                                t,
                                u64::from_le_bytes(d.bytes[..8].try_into().unwrap()),
                            );

                            if event {
                                extended(
                                    frame,
                                    0,
                                    u64::from_le_bytes(d.bytes[..8].try_into().unwrap()),
                                    t.diagnostic_id(),
                                );
                                frame.registers[11] = p.diagnostic_id();
                            } else {
                                scalar(
                                    frame,
                                    0,
                                    u64::from_le_bytes(d.bytes[..8].try_into().unwrap()),
                                );
                                frame.registers[11] = d.capability.map_or(0, |h| h.0);
                            }
                        }
                        Err(IpcError::Empty) => {
                            if event {
                                extended(frame, 2, 0, 0)
                            } else {
                                scalar(frame, 2, 0)
                            }
                        }
                        Err(_) => {
                            if event {
                                extended(frame, 1, 0, 0)
                            } else {
                                scalar(frame, 1, 0)
                            }
                        }
                    }
                } else {
                    scalar(frame, 1, 0)
                }
            }
            Ok(Call::DisplayInfo { capability, field }) => {
                match self
                    .backing
                    .device
                    .mapped_information(self.a, m.domain, capability)
                {
                    Ok(info) => scalar(
                        frame,
                        0,
                        match field {
                            1 => {
                                self.actors[index - 1]
                                    .as_ref()
                                    .unwrap()
                                    .image()
                                    .unwrap()
                                    .root()
                                    .base()
                                    + 4 * 1024 * 1024
                                    + u64::from(info.byte_offset)
                            }
                            2 => info.width as u64,
                            3 => info.height as u64,
                            4 => info.stride as u64,
                            5 => u64::from(info.byte_length),
                            6 => u64::from(info.format),
                            _ => 0,
                        },
                    ),
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::PortInput {
                capability,
                port,
                width,
            }) => {
                let request = ev_kernel::io_ports::Request {
                    capability,
                    port,
                    width,
                };
                match self.backing.ports.input(
                    ev_kernel::io_ports::Caller {
                        authority: self.a,
                        scheduler: self.s,
                        rpc: self.rpc,
                        cpu: 0,
                    },
                    request,
                ) {
                    Ok(permit) => {
                        // SAFETY: actual scheduler-bound live permit, assigned device.
                        let value = unsafe { crate::port_io::input(permit) };
                        extended(frame, 0, value as u64, 0);
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(Call::PortOutput {
                capability,
                port,
                width,
                value,
            }) => {
                let request = ev_kernel::io_ports::Request {
                    capability,
                    port,
                    width,
                };
                match self.backing.ports.output(
                    ev_kernel::io_ports::Caller {
                        authority: self.a,
                        scheduler: self.s,
                        rpc: self.rpc,
                        cpu: 0,
                    },
                    request,
                    value,
                ) {
                    Ok(permit) => {
                        // SAFETY: typed actual port/width/value permit, serialized IF0.
                        unsafe { crate::port_io::output(permit) };
                        extended(frame, 0, 0, 0);
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(Call::StopProcess(cap)) if index == 0 => {
                let result = self
                    .find_control(m.domain, cap)
                    .and_then(|i| self.stop_actor(i));
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Reap(cap)) if index == 0 => {
                let result = self.find_control(m.domain, cap).and_then(|i| {
                    // SAFETY: reap checks actual stopped owner plus no pending RPC;
                    // controller root is restored and every frame claim retained.
                    unsafe { self.reap_actor(i, frames) }
                });
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Observe(cap)) if index == 0 => {
                match self.registry.observe(self.a, self.s, m.domain, cap) {
                    Ok(dead) => scalar(frame, 0, u64::from(dead)),
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::ProcessIdentity(cap)) if index == 0 => {
                if cfg!(feature = "test-m5-native") && cap.0 == 0 {
                    ev_kernel::user_context::reply_native_root_identity(
                        frame,
                        m.process.diagnostic_id(),
                        m.thread.diagnostic_id(),
                        now,
                    );
                    #[cfg(feature = "test-m5-native")]
                    if let Some(native) = &mut self.native
                        && native.boot_mode != root_v2::native::catalogue::BootMode::Standalone
                    {
                        native.self_identity_queries = native
                            .self_identity_queries
                            .checked_add(1)
                            .expect("bounded actual self query sequence");
                        assert!(
                            native.self_identity_queries <= 32,
                            "Native actual Root self query evidence budget exhausted"
                        );
                        (self.observations)(Observation::NativeSelfIdentity(NativeSelfIdentity {
                            sequence: native.self_identity_queries,
                            process: m.process.diagnostic_id(),
                            thread: m.thread.diagnostic_id(),
                            root_epoch: EPOCH.get(),
                            root_incarnation: self.root.active.as_ref().unwrap().token().number(),
                            root_manifest_sha256: native.root_manifest_sha256,
                            tick: now,
                        }));
                    }
                } else {
                    match self.find_control(m.domain, cap) {
                        Ok(i) if self.actors[i - 1].as_ref().unwrap().admitted => {
                            let m = self.metadata(i).unwrap();
                            scalar(frame, 0, m.process.diagnostic_id());
                            frame.registers[11] = m.thread.diagnostic_id();
                        }
                        _ => scalar(frame, 1, 0),
                    }
                }
            }
            Ok(Call::ObserveField { process, field }) if index == 0 => {
                let record = self
                    .find_control(m.domain, process)
                    .ok()
                    .and_then(|i| self.actors[i - 1].as_ref().unwrap().fault);
                if let Some(r) = record {
                    scalar(
                        frame,
                        0,
                        match field {
                            1 => r.process,
                            2 => r.thread,
                            3 => r.vector,
                            4 => r.error,
                            5 => r.address,
                            6 => r.instruction,
                            _ => 0,
                        },
                    )
                } else {
                    scalar(frame, 2, 0)
                }
            }
            Ok(Call::Close(cap)) => {
                let result = self.a.close(m.domain, cap);
                self.collect_closed();
                self.collect_channels();
                self.collect_jobs();
                scalar(frame, u64::from(result.is_err()), 0);
            }
            #[cfg(feature = "test-m5-native")]
            Ok(Call::Exit(0)) if index == 0 && self.native.is_some() => {
                assert!(
                    self.native.as_ref().unwrap().finish_requested,
                    "native Root Exit0 without actual completion request"
                );
                assert!(
                    !self.native.as_ref().unwrap().report.pending()
                        && !self.native.as_ref().unwrap().report_error
                        && !self.native.as_ref().unwrap().diagnostics.pending()
                        && !self.native.as_ref().unwrap().diagnostic_error,
                    "native Root completion requires full ordered diagnostic frames"
                );
                assert_eq!(self.rpc.outstanding(), 0);
                assert!(self.pending.iter().all(Option::is_none));
                assert_eq!(self.s.exit(0), Ok(m.thread));
                self.native.as_mut().unwrap().root_exited = true;
                return true;
            }
            Ok(Call::Exit(code)) if index == Child::App.index() + 1 => {
                (self.observations)(Observation::VoluntaryExit(VoluntaryExit {
                    process: m.process.diagnostic_id(),
                    thread: m.thread.diagnostic_id(),
                    code,
                    instruction: frame.rip,
                    calls: self.facts.calls,
                    replies: self.facts.replies,
                }));
                assert_eq!(self.s.exit(0), Ok(m.thread));
                self.stop_actor(index).unwrap();
                return true;
            }
            Ok(Call::Exit(code)) => panic!("desktop critical Exit index={index} code={code}"),
            _ => scalar(frame, 1, 0),
        }
        false
    }
    fn bind_receiver(
        &mut self,
        index: usize,
        endpoint: Handle,
        process: Handle,
        frame: &mut UserContext,
    ) {
        let caller = self.current(index);
        let Some(w) = self.wire(
            caller,
            endpoint,
            if process.0 == 0 {
                RECEIVE
            } else {
                Rights::CONTROL
            },
        ) else {
            scalar(frame, 1, 0);
            return;
        };
        let target = if process.0 == 0 {
            Some(caller)
        } else if index == 0 {
            self.find_control(caller.domain, process)
                .ok()
                .and_then(|i| self.metadata(i))
        } else {
            None
        };
        let Some(target) = target else {
            scalar(frame, 1, 0);
            return;
        };
        let receive = if process.0 == 0 {
            Some(endpoint)
        } else {
            self.find_control(caller.domain, process)
                .ok()
                .and_then(|i| {
                    let child = self.actors[i - 1].as_ref().unwrap().child;
                    root_v2::graph::grants(child)
                        .iter()
                        .enumerate()
                        .find_map(|(j, g)| match g.source {
                            root_v2::graph::Source::Endpoint(c)
                                if c.index() == w && g.rights == 272 =>
                            {
                                self.registry
                                    .grant(self.a, caller.domain, process, (j + 1) as u64)
                                    .ok()
                            }
                            _ => None,
                        })
                })
        };
        let Some(receive) = receive else {
            scalar(frame, 1, 0);
            return;
        };
        if w == Channel::GrantInbox.index() && index == 0 && process.0 != 0 {
            // Exact held target/RX grant verified above. The selected policy's
            // physical destination is installed at Start before first dispatch.
            let wire = self.wires[w].as_mut().unwrap();
            wire.control = Some(endpoint);
            wire.receiver = target.domain;
            scalar(frame, 0, 0);
            return;
        }
        let wire = self.wires[w].as_mut().unwrap();
        if wire
            .bind(self.a, caller.domain, endpoint, target, receive)
            .is_err()
        {
            scalar(frame, 2, 0);
            return;
        }
        let is_rpc = matches!(w, 0 | 1 | 2 | 3 | 5 | 9 | 10 | 11 | 12 | 13 | 14);
        if is_rpc && wire.bound != Some(target.thread) {
            if self
                .rpc
                .bind_endpoint(
                    self.a,
                    target.domain,
                    receive,
                    target.thread,
                    Policy::new(8, 0).unwrap(),
                )
                .is_err()
            {
                scalar(frame, 1, 0);
                return;
            }
            wire.bound = Some(target.thread);
        }
        scalar(frame, 0, 0);
    }
}
