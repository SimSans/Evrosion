//! Fixture-only, finite actual startup phase facts. No serial output here:
//! rows remain local until an ordinary typed System outcome is accepted.
use super::*;
use ev_kernel::startup_trace::{
    CpuPoint, CpuSample, Row, cpu_sample, initial_note_reply, present_request, startup_token,
};

impl Runtime<'_, '_> {
    fn startup_cpu(&self, subject: Metadata) -> Option<CpuSample> {
        let actor = self.actors[Child::App.index()].as_ref()?;
        if !actor.admitted
            || actor.retired
            || actor.running.is_none()
            || (subject.process, subject.thread, subject.job)
                != (actor.meta.process, actor.meta.thread, actor.meta.job)
        {
            return None;
        }
        cpu_sample(self.s, subject.process, subject.thread, subject.job)
    }
    fn startup_cpu_point(&self, row: &Row, app: Metadata) -> CpuPoint {
        CpuPoint {
            phase: row.phase,
            tick: row.tick,
            process: row.process,
            thread: row.thread,
            job: app.job.diagnostic_id(),
            ticket: row.ticket,
            call_epoch: row.call_epoch,
            call: row.call,
            sample: self.startup_cpu(app),
        }
    }
    pub(super) fn startup_recording(&self) -> bool {
        self.startup_trace.recording()
            && self.native.as_ref().is_some_and(|native| {
                native.boot_mode == root_v2::native::catalogue::BootMode::SystemManaged
            })
    }
    pub(super) fn startup_event(
        &mut self,
        phase: u8,
        wire: usize,
        sender: (ProcessId, ThreadId),
        value: u64,
        delivery: (Ticket, u64),
    ) {
        if !self.startup_recording() || wire != 15 || !startup_token(value.to_le_bytes()) {
            return;
        }
        let Some(actor) = self.actors[Child::App.index()].as_ref() else {
            return;
        };
        if !actor.admitted
            || actor.retired
            || actor.running.is_none()
            || sender != (actor.meta.process, actor.meta.thread)
        {
            return;
        }
        let peer = self.root.meta;
        self.startup_trace.push(Row {
            phase,
            wire: wire as u8,
            tick: delivery.1,
            process: sender.0.diagnostic_id(),
            thread: sender.1.diagnostic_id(),
            peer_process: peer.process.diagnostic_id(),
            peer_thread: peer.thread.diagnostic_id(),
            endpoint: self.wires[wire].as_ref().unwrap().object as u64,
            ticket: delivery.0.0,
            value,
            ..Row::default()
        });
    }
    /// Called only from the existing actual current Root→App Note delivery
    /// recognizer. This samples no shared body and grants no Read authority.
    pub(super) fn startup_note_delivered(
        &mut self,
        sender: Metadata,
        app: Metadata,
        delivery: (usize, Ticket, u64, u64),
    ) {
        let (wire, ticket, value, tick) = delivery;
        if !self.startup_recording()
            || wire != Channel::AppControl.index()
            || (sender.process, sender.thread) != (self.root.meta.process, self.root.meta.thread)
            || !initial_note_reply(value)
        {
            return;
        }
        let Some(actor) = self.actors[Child::App.index()].as_ref() else {
            return;
        };
        if !actor.admitted
            || actor.retired
            || actor.running.is_none()
            || (app.process, app.thread, app.job)
                != (actor.meta.process, actor.meta.thread, actor.meta.job)
        {
            return;
        }
        if !self.startup_trace.select_note() {
            return;
        }
        let row = Row {
            phase: 9,
            wire: wire as u8,
            tick,
            process: app.process.diagnostic_id(),
            thread: app.thread.diagnostic_id(),
            peer_process: sender.process.diagnostic_id(),
            peer_thread: sender.thread.diagnostic_id(),
            endpoint: self.wires[wire].as_ref().unwrap().object as u64,
            ticket: ticket.0,
            value,
            ..Row::default()
        };
        self.startup_trace
            .push_cpu(self.startup_cpu_point(&row, app));
        self.startup_trace.push(row);
    }
    pub(super) fn startup_present_row(&self, p: Pending, phase: u8) -> Option<Row> {
        if !self.startup_recording()
            || p.caller != Child::App.index() + 1
            || p.callee != Child::Display.index() + 1
            || p.wire != Channel::AppPresent.index()
            || !present_request(p.value)
            || !self
                .startup_trace
                .selected_present(p.id.epoch().get(), p.id.serial())
        {
            return None;
        }
        let caller = self.metadata(p.caller)?;
        let callee = self.metadata(p.callee)?;
        Some(Row {
            phase,
            wire: p.wire as u8,
            process: caller.process.diagnostic_id(),
            thread: caller.thread.diagnostic_id(),
            peer_process: callee.process.diagnostic_id(),
            peer_thread: callee.thread.diagnostic_id(),
            endpoint: self.wires[p.wire].as_ref()?.object as u64,
            ticket: p.ticket.0,
            call_epoch: p.id.epoch().get(),
            call: p.id.serial(),
            value: p.value,
            ..Row::default()
        })
    }
    pub(super) fn startup_present(&mut self, p: Pending, phase: u8, tick: u64) {
        if let Some(mut row) = self.startup_present_row(p, phase) {
            row.tick = tick;
            if phase == 3 {
                let app = self.metadata(p.caller).unwrap();
                self.startup_trace
                    .push_cpu(self.startup_cpu_point(&row, app));
            }
            self.startup_trace.push(row);
        }
    }
    pub(super) fn startup_present_now(&mut self, p: Pending, phase: u8) {
        if let Some(mut row) = self.startup_present_row(p, phase) {
            row.tick = crate::timer::now();
            self.startup_trace.push(row);
        }
    }
    pub(super) fn startup_flush(&mut self) {
        if !self.startup_recording() || !self.startup_trace.close() {
            return;
        }
        let (observed, retained, overflow) = self.startup_trace.counts();
        for index in 0..retained {
            (self.observations)(Observation::StartupPhase(
                self.startup_trace.row(index).unwrap(),
            ));
        }
        (self.observations)(Observation::StartupPhaseCounts {
            observed,
            retained,
            overflow,
        });
        let (observed, retained, duplicates, overflow) = self.startup_trace.cpu_counts();
        for index in 0..retained {
            (self.observations)(Observation::StartupCpu(
                self.startup_trace.cpu_point(index).unwrap(),
            ));
        }
        (self.observations)(Observation::StartupCpuCounts {
            observed,
            retained,
            duplicates,
            overflow,
        });
    }
}
