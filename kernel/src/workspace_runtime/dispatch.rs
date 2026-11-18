//! Every authority/domain/identity below derives from the actual captured
//! dispatched owner, never a packet PID or request's descriptive source ID.
use super::*;
impl World {
    pub(super) fn syscall(
        &mut self,
        index: usize,
        frame: &mut UserContext,
        frames: &mut BootstrapFrames,
        log: &mut dyn Write,
    ) -> bool {
        use ev_userspace_contract::syscall as abi;
        let m = self.current(index);
        let now = crate::timer::now();
        let call = decode(frame);
        if matches!(
            frame.registers[14],
            abi::SESSION_POWER_INFO | abi::SESSION_POWER
        ) {
            let (status, value) = match call {
                Ok(Call::SessionPowerInfo { restart: false }) if index == 0 => {
                    (0, abi::SESSION_POWER_V1)
                }
                Ok(Call::SessionPowerReady {
                    nonce,
                    frame,
                    input,
                }) => match self.power_dialog_report(index, nonce, frame, input, log) {
                    Ok(value) => (0, value),
                    Err(status) => (status, 0),
                },
                Ok(Call::SessionPowerInfo { restart: true })
                    if index == 0 && Self::restart_supported() =>
                {
                    (0, abi::SESSION_POWER_RESTART_V1)
                }
                Ok(Call::SessionPower {
                    operation,
                    block,
                    nic,
                    extra,
                }) => match self.session_power(index, operation, block, nic, extra, log) {
                    Ok(value) => (0, value),
                    Err(status) => (status, 0),
                },
                _ => (1, 0),
            };
            // Also clears the input R10 on malformed/denied tagged calls.
            ev_kernel::user_context::reply_session_power(frame, status, value);
            return false;
        }
        if call
            .as_ref()
            .is_ok_and(|call| !self.power_call_allowed(call, now))
        {
            scalar(frame, 4, 0);
            return false;
        }
        match call {
            Ok(Call::SessionPowerReady { .. }) => unreachable!(),
            Ok(Call::ManagedSendRetireInfo) if index == 0 => {
                scalar(frame, 0, abi::MANAGED_SEND_RETIRE_V1)
            }
            Ok(Call::ManagedSendRetire { process, nonce }) => {
                match self.managed_send_retire(index, process, nonce) {
                    Ok(state) => scalar(frame, 0, state as u64),
                    Err(e) => scalar(frame, e, 0),
                }
            }
            Ok(call @ Call::ImageControl { .. }) if index == 0 => {
                self.image_control(m, frame, frames, call, now, log);
            }
            Ok(Call::PrepareWorkspaceProcess { creator, process }) if index == 0 => {
                let permitted = self
                    .root
                    .active
                    .as_ref()
                    .and_then(|active| {
                        active
                            .workspace_dynamic_image_permit(
                                self.core.a,
                                self.core.s,
                                m.domain,
                                creator,
                                m.thread,
                            )
                            .ok()
                    })
                    .is_some();
                let target = self
                    .find_control(m.domain, process)
                    .ok()
                    .and_then(|i| self.actors[i - 1].as_ref());
                let eligible = target.is_some_and(|actor| {
                    actor.child.image_slot() == ImageSlot::Editor && actor.bound
                });
                let result = if permitted && eligible {
                    // SAFETY: actual captured Root+Creator permit, exact held
                    // File App and exclusive physical allocator/controller.
                    unsafe { self.prepare_process(m.domain, process, frames, log) }
                } else {
                    Err(2)
                };
                frame.registers[5] = 0;
                match result {
                    Ok(()) => scalar(frame, 0, 0),
                    Err(reason) => scalar(frame, 1, reason),
                }
            }
            Ok(Call::Yield) => scalar(frame, 0, 0),
            Ok(Call::Monotonic) => scalar(frame, 0, now),
            Ok(Call::SelfIdentityInfo) => scalar(frame, 0, abi::SELF_IDENTITY_V1),
            Ok(Call::SelfIdentity { field }) => match self.core.rpc.self_identity(
                self.core.a,
                self.core.s,
                m.thread,
                m.domain,
                field,
            ) {
                Ok(value) => scalar(frame, 0, value),
                Err(_) => scalar(frame, 1, 0),
            },
            Ok(Call::ServingOriginInfo) => scalar(frame, 0, abi::SERVING_ORIGIN_V1),
            Ok(Call::ServingOrigin {
                endpoint,
                nonce,
                field,
            }) => {
                let actual = self.wire(m, endpoint, Rights::RECEIVE).and_then(|wire| {
                    let held = self
                        .core
                        .a
                        .authorize(m.domain, endpoint, Kind::Endpoint, Rights::RECEIVE)
                        .ok()?
                        .identity();
                    let serving = self.core.rpc.serving(m.thread)?;
                    self.pending.iter().flatten().find(|p| {
                        p.callee == index
                            && p.delivered
                            && p.wire == wire
                            && p.id == serving
                            && p.id.serial() == nonce
                            && self.wires[wire].as_ref().is_some_and(|w| w.object == held)
                    })?;
                    let origin = self
                        .core
                        .rpc
                        .serving_origin(
                            self.core.a,
                            self.core.s,
                            ev_kernel::rpc::ServingReceiver {
                                thread: m.thread,
                                space: m.domain,
                                endpoint,
                                nonce,
                            },
                            now,
                        )
                        .ok()?;
                    (origin.endpoint_object == held as u64)
                        .then(|| origin.field(field))
                        .flatten()
                });
                scalar(frame, u64::from(actual.is_none()), actual.unwrap_or(0));
            }
            Ok(Call::ProcessJobInfoInfo) => extended(frame, 0, abi::PROCESS_JOB_INFO_V1, 0),
            Ok(Call::ProcessJobInfo { capability, field }) => {
                match ev_kernel::job_info::inspect_process(
                    self.core.a,
                    self.core.s,
                    self.core.registry,
                    m,
                    capability,
                    field,
                ) {
                    Ok(value) => scalar(frame, 0, value),
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::JobInfo { capability, field }) => match ev_kernel::job_info::inspect(
                self.core.a,
                self.core.s,
                self.core.registry,
                m,
                capability,
                field,
            ) {
                Ok(value) => scalar(frame, 0, value),
                Err(_) => scalar(frame, 1, 0),
            },
            Ok(Call::ProcessIdentity(cap)) => {
                let selected = if cap.0 == 0 && index == 0 {
                    Some(m)
                } else {
                    self.core.registry.metadata(self.core.a, m.domain, cap).ok()
                };
                if let Some(meta) = selected {
                    extended(
                        frame,
                        0,
                        meta.process.diagnostic_id(),
                        if index == 0 && cap.0 == 0 {
                            now
                        } else {
                            frame.registers[5]
                        },
                    );
                    frame.registers[11] = meta.thread.diagnostic_id();
                } else {
                    scalar(frame, 1, 0)
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
                .any(|k| {
                    self.core
                        .a
                        .authorize(m.domain, capability, k, rights)
                        .is_ok()
                });
                scalar(frame, u64::from(!allowed), 0);
            }
            Ok(Call::CreateJob { creator, template }) if index == 0 => {
                let result = self
                    .jobs
                    .iter()
                    .position(Option::is_none)
                    .ok_or(2u64)
                    .and_then(|slot| {
                        let cap = self
                            .core
                            .registry
                            .create_job(self.core.a, self.core.s, m.domain, creator, template)
                            .map_err(|_| 1u64)?;
                        self.jobs[slot] = Some(
                            self.core
                                .registry
                                .job_id(self.core.a, m.domain, cap)
                                .unwrap(),
                        );
                        Ok(cap)
                    });
                match result {
                    Ok(cap) => scalar(frame, 0, cap.0),
                    Err(e) => scalar(frame, e, 0),
                }
            }
            Ok(Call::CreateProcess { job, image }) if index == 0 => {
                match self.create_process(m.domain, job, image) {
                    Ok(cap) => {
                        scalar(frame, 0, cap.0);
                        if let Ok(i) = self.find_control(m.domain, cap) {
                            self.event(log, "held", i);
                        }
                    }
                    Err(e) => scalar(frame, e, 0),
                }
            }
            Ok(Call::Delegate {
                process,
                source,
                selector,
            }) if index == 0 => match self.delegate_child(m.domain, process, source, selector) {
                Ok(cap) => scalar(frame, 0, cap.0),
                Err(reason) => scalar(frame, reason, 0),
            },
            Ok(Call::Start(cap)) if index == 0 => {
                // SAFETY: actual RootCONTROL resolves a held declared actor;
                // this controller exclusively owns its physical slot/allocator.
                let result = unsafe { self.start(m.domain, cap, frames, log) };
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::CreateEndpoint(job)) if index == 0 => {
                let slot = (0..23).find(|&i| self.wires[i].is_none());
                if let Some(slot) = slot {
                    match self
                        .core
                        .registry
                        .create_channel(self.core.a, m.domain, job)
                    {
                        Ok((cap, mailbox)) => {
                            let object = self
                                .core
                                .a
                                .authorize(m.domain, cap, Kind::Endpoint, Rights::CONTROL)
                                .unwrap()
                                .identity();
                            self.wires[slot] = Some(Wire::new(
                                object,
                                m.domain,
                                mailbox,
                                Channel::from_wire_index(slot).unwrap().delivery(),
                            ));
                            scalar(frame, 0, cap.0)
                        }
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 2, 0)
                }
            }
            Ok(Call::BindReceiver { endpoint, process }) => scalar(
                frame,
                self.bind_receiver(index, endpoint, process)
                    .err()
                    .unwrap_or(0),
                0,
            ),
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
                    .core
                    .rpc
                    .serving(m.thread)
                    .and_then(|id| self.core.rpc.context(id).ok())
                    .map(|c| c.deadline.tick());
                scalar(frame, u64::from(deadline.is_none()), deadline.unwrap_or(0));
            }
            Ok(Call::EnqueueManagedRead {
                process,
                source,
                inbox,
                nonce,
            }) => self.grant_selected(index, process, source, inbox, nonce, frame),
            Ok(Call::InhibitManagedProcess(cap)) if index == 0 => {
                let result = self.find_control(m.domain, cap).and_then(|i| {
                    self.actors[i - 1]
                        .as_mut()
                        .unwrap()
                        .running
                        .as_mut()
                        .ok_or(1u64)?
                        .inhibit(self.core.s)
                        .map_err(|_| 1u64)
                });
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Send {
                endpoint,
                value,
                capability: None,
            }) => {
                let sender = if index == 0 {
                    graph::Sender::Root
                } else {
                    graph::Sender::Child(self.actors[index - 1].as_ref().unwrap().child)
                };
                let result = self
                    .wire(m, endpoint, Rights::SEND)
                    .filter(|&w| {
                        w == graph::ROOT_EVENTS_WIRE
                            || Channel::from_wire_index(w).is_some_and(|c| {
                                c.delivery() == DeliveryMode::Async && c.allows(sender)
                            })
                    })
                    .ok_or(IpcError::WrongOwner)
                    .and_then(|w| {
                        self.wires[w].as_mut().unwrap().send(
                            self.core.a,
                            m,
                            endpoint,
                            value,
                            Deadline::after(now, 9728).unwrap(),
                            now,
                        )
                    });
                scalar(
                    frame,
                    match result {
                        Ok(_) => 0,
                        Err(IpcError::Full | IpcError::Closed) => 2,
                        Err(_) => 1,
                    },
                    0,
                );
            }
            Ok(call @ Call::Receive(_) | call @ Call::ReceiveEvent(_)) => {
                let (cap, event) = match call {
                    Call::Receive(cap) => (cap, false),
                    Call::ReceiveEvent(cap) => (cap, true),
                    _ => unreachable!(),
                };
                if !event && self.receive_selected(index, cap, frame) {
                    return false;
                }
                if let Some(w) = self.wire(m, cap, RECEIVE) {
                    match self.wires[w]
                        .as_mut()
                        .unwrap()
                        .receive_async_at(self.core.a, m, cap, now)
                    {
                        Ok(received) => {
                            if let Some((d, p, t)) = received.delivery {
                                // One narrow actual receipt diagnostic: never
                                // infer a sender from event bytes or log input.
                                if event
                                    && w == graph::ROOT_EVENTS_WIRE
                                    && d.length == 8
                                    && d.bytes[..3] == [b'E', b'5', 7]
                                {
                                    let _ = writeln!(
                                        log,
                                        "EVROSION_M8_APP_REFUSED process={} thread={} reason={} tick={now}",
                                        p.diagnostic_id(),
                                        t.diagnostic_id(),
                                        d.bytes[3]
                                    );
                                }
                                if event
                                    && w == graph::ROOT_EVENTS_WIRE
                                    && d.length == 8
                                    && d.bytes[..2] == *b"WF"
                                    && self.actors[Child::Workspace.index()].as_ref().is_some_and(
                                        |actor| actor.meta.process == p && actor.meta.thread == t,
                                    )
                                {
                                    let word =
                                        u32::from_le_bytes(d.bytes[4..8].try_into().unwrap());
                                    let _ = writeln!(
                                        log,
                                        "EVROSION_M8_WORKSPACE_FAILURE process={} thread={} field={} detail={} word={word} tick={now}",
                                        p.diagnostic_id(),
                                        t.diagnostic_id(),
                                        d.bytes[2],
                                        d.bytes[3]
                                    );
                                }
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
                            } else if event {
                                extended(frame, 2, 0, 0)
                            } else {
                                scalar(frame, 2, 0)
                            }
                        }
                        Err(IpcError::Empty) => scalar(frame, 2, 0),
                        Err(_) => scalar(frame, 1, 0),
                    }
                } else {
                    scalar(frame, 1, 0)
                }
            }
            Ok(Call::Observe(cap)) => {
                match self
                    .core
                    .registry
                    .observe(self.core.a, self.core.s, m.domain, cap)
                {
                    Ok(stopped) => scalar(frame, 0, u64::from(stopped)),
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::StopProcess(cap)) if index == 0 => {
                let result = self
                    .find_control(m.domain, cap)
                    .and_then(|i| self.stop_actor(i, log));
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Reap(cap)) if index == 0 => {
                let result = self.find_control(m.domain, cap).and_then(|i| {
                    // SAFETY: actual RootCONTROL target; reap independently
                    // checks stopped ownership and accepted-call fencing.
                    unsafe { self.reap_actor(i, frames, log) }
                });
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Close(cap)) => {
                let result = if index == 0 && self.dynamic.handle_busy(cap) {
                    Err(ev_kernel::capability::Error::Denied)
                } else {
                    self.core.a.close(m.domain, cap)
                };
                scalar(frame, u64::from(result.is_err()), 0);
                self.collect();
            }
            Ok(Call::FaultInfo { capability, field }) => {
                let value = self.find_control(m.domain, capability).ok().and_then(|i| {
                    let actor = self.actors[i - 1].as_ref()?;
                    actor
                        .fault?
                        .context_field(actor.meta.job, &actor.context, field)
                });
                scalar(frame, u64::from(value.is_none()), value.unwrap_or(0));
            }
            Ok(Call::DisplayInfo { capability, field }) => {
                let result = self
                    .core
                    .backing
                    .device
                    .as_ref()
                    .unwrap()
                    .mapped_information(self.core.a, m.domain, capability);
                match result {
                    Ok(info) => {
                        let base = (self.actors[index - 1]
                            .as_ref()
                            .unwrap()
                            .running
                            .as_ref()
                            .unwrap()
                            .image()
                            .owner
                            .information(m)
                            .entry
                            >> 39)
                            << 39;
                        scalar(
                            frame,
                            0,
                            match field {
                                1 => base + 4 * 1024 * 1024 + u64::from(info.byte_offset),
                                2 => u64::from(info.width),
                                3 => u64::from(info.height),
                                4 => u64::from(info.stride),
                                5 => u64::from(info.byte_length),
                                6 => u64::from(info.format),
                                _ => 0,
                            },
                        )
                    }
                    Err(_) => scalar(frame, 1, 0),
                }
            }
            Ok(Call::PortWords256Info) if self.selected_block(index) => {
                extended(frame, 0, abi::PORT_WORDS256_V1, 0)
            }
            Ok(call @ (Call::PortInputWords256 { .. } | Call::PortOutputWords256 { .. })) => {
                let status = u64::from(self.port_words256(index, call, now).is_err());
                if status != 0 {
                    self.facts.pio.denials = self
                        .facts
                        .pio
                        .denials
                        .checked_add(1)
                        .expect("PIO denial count overflow");
                }
                extended(frame, status, 0, 0)
            }
            Ok(Call::PortBatchInfo) => extended(frame, 0, abi::PORT_BATCH_V1, 0),
            Ok(Call::PortByteBatchInfo) => extended(frame, 0, abi::PORT_BYTE_BATCH_V1, 0),
            Ok(Call::PortInput {
                capability,
                port,
                width,
            }) => {
                let result = self.core.backing.ports.input(
                    ev_kernel::io_ports::Caller {
                        authority: self.core.a,
                        scheduler: self.core.s,
                        rpc: self.core.rpc,
                        cpu: 0,
                    },
                    ev_kernel::io_ports::Request {
                        capability,
                        port,
                        width,
                    },
                );
                match result {
                    Ok(permit) => {
                        // SAFETY: exact live typed port/width permit, exclusive
                        // assigned device and IF0 captured controller.
                        let value = unsafe { crate::port_io::input(permit) };
                        extended(frame, 0, u64::from(value), 0)
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
                let result = self.core.backing.ports.output(
                    ev_kernel::io_ports::Caller {
                        authority: self.core.a,
                        scheduler: self.core.s,
                        rpc: self.core.rpc,
                        cpu: 0,
                    },
                    ev_kernel::io_ports::Request {
                        capability,
                        port,
                        width,
                    },
                    value,
                );
                match result {
                    Ok(permit) => {
                        // SAFETY: actual live typed range/value permit under
                        // serialized IF0 hardware ownership.
                        unsafe { crate::port_io::output(permit) };
                        extended(frame, 0, 0, 0)
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(Call::PortInputWords4 {
                capability,
                port,
                deadline,
            }) => {
                let result = self.core.backing.ports.input_words4(
                    ev_kernel::io_ports::Caller {
                        authority: self.core.a,
                        scheduler: self.core.s,
                        rpc: self.core.rpc,
                        cpu: 0,
                    },
                    ev_kernel::io_ports::Request {
                        capability,
                        port,
                        width: 2,
                    },
                    deadline,
                    now,
                );
                match result {
                    Ok(permit) => {
                        // SAFETY: fixed four-word same-port permit/deadline,
                        // actual assigned device and captured IF0 ownership.
                        extended(frame, 0, unsafe { crate::port_io::input_words4(permit) }, 0)
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(call @ (Call::PortOutputWords4 { .. } | Call::PortOutputBytes4 { .. })) => {
                let result = self.core.backing.ports.output_batch_call(
                    ev_kernel::io_ports::Caller {
                        authority: self.core.a,
                        scheduler: self.core.s,
                        rpc: self.core.rpc,
                        cpu: 0,
                    },
                    call,
                    now,
                );
                match result {
                    Ok(ev_kernel::io_ports::OutputBatchPermit::Words(permit)) => {
                        // SAFETY: decoded payload/deadline and current actual
                        // caller are checked by the same real borrowed permit.
                        unsafe { crate::port_io::output_words4(permit) };
                        extended(frame, 0, 0, 0)
                    }
                    Ok(ev_kernel::io_ports::OutputBatchPermit::Bytes(permit)) => {
                        // SAFETY: exact fixed byte batch and live current port
                        // scope were checked before the first device effect.
                        unsafe { crate::port_io::output_bytes4(permit) };
                        extended(frame, 0, 0, 0)
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(Call::PortInputBytes4 {
                capability,
                port,
                deadline,
            }) => {
                let result = self.core.backing.ports.input_bytes4(
                    ev_kernel::io_ports::Caller {
                        authority: self.core.a,
                        scheduler: self.core.s,
                        rpc: self.core.rpc,
                        cpu: 0,
                    },
                    ev_kernel::io_ports::Request {
                        capability,
                        port,
                        width: 1,
                    },
                    deadline,
                    now,
                );
                match result {
                    Ok(permit) => {
                        // SAFETY: exact four-byte same-port permit/deadline,
                        // captured IF0 controller and assigned device.
                        let value = unsafe { crate::port_io::input_bytes4(permit) };
                        extended(frame, 0, u64::from(value), 0)
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(Call::Exit(code)) => {
                let _ = writeln!(
                    log,
                    "EVROSION_M8_KERNEL_EXIT actor={index} process={} thread={} code={code} tick={now}",
                    m.process.diagnostic_id(),
                    m.thread.diagnostic_id()
                );
                self.contain(index, frame, None, log);
                return true;
            }
            _ => scalar(frame, 1, 0),
        }
        false
    }
}
