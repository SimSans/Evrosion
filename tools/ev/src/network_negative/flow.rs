use super::{
    cases,
    fixture::Snapshot,
    link_loss,
    note::{self, Work},
    records,
};
use crate::{
    build::Result, network_io::components::Context, network_negative_contract::Goal, qmp::Qmp,
    storage,
};
use serde_json::{Value, json};
use std::{io::Write, path::Path};

pub(super) struct Flow {
    stage: u8,
    goal: Goal,
    work: Option<Work>,
    baseline: Option<Vec<u8>>,
    link_loss: Option<link_loss::Capture>,
    pub inputs: Vec<Value>,
    pub finish_sent: bool,
}
impl Flow {
    pub(super) fn new(goal: Goal) -> Self {
        Self {
            stage: 0,
            goal,
            work: None,
            baseline: None,
            link_loss: None,
            inputs: Vec::new(),
            finish_sent: false,
        }
    }
    fn send(&mut self, input: &mut impl Write, command: &str) -> Result<()> {
        input
            .write_all(command.as_bytes())
            .and_then(|()| input.flush())
            .map_err(|e| e.to_string())?;
        self.inputs.push(json!({"command":command,"stage":self.stage,"scripted_input":true,"human_consent_claim":false}));
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn advance(
        &mut self,
        serial: &[u8],
        build: &str,
        context: &Context,
        fixture: &Snapshot,
        input: &mut impl Write,
        qmp: &mut Qmp,
        disk: &storage::Disk,
        directory: &Path,
    ) -> Result<()> {
        if let Some(error) = &fixture.error {
            return Err(format!("negative HTTP peer: {error}"));
        }
        if fixture.accepted > if self.goal == Goal::AppDenial { 1 } else { 2 }
            || fixture.hello_completed > if self.goal == Goal::Destination { 2 } else { 1 }
            || fixture.pending_accepted > 1
        {
            return Err("negative fixture extra socket/request".into());
        }
        if !actual_context(serial, build, context)? {
            return Ok(());
        }
        let network = crate::network_protocol::records(serial, build)?;
        if self.stage < 4
            && (network.iter().any(|r| r.stage == 8)
                || !crate::network_error_protocol::records(serial, build)?.is_empty())
        {
            return Err("negative initial network failed before its explicit test".into());
        }
        let rows = crate::native_protocol::states_network(serial, build)?;
        let observed = records::prefix(serial, build, Some(&context.images))?;
        match self.stage {
            0 => {
                if network.last().is_some_and(|p| p.stage == 6) && fixture.hello_completed == 1 {
                    self.send(input, "install a\n")?;
                    self.stage = 1;
                }
            }
            1 => {
                if let Some(r) = reply(&rows, "install")? {
                    if r.fields["staged"] != "a" || r.number("revision")? != 1 {
                        return Err("negative initial install differs".into());
                    }
                    self.send(input, "activate\n")?;
                    self.stage = 2;
                }
            }
            2 => {
                if let Some(r) = reply(&rows, "activate")? {
                    if r.fields["active"] != "a"
                        || r.fields["actual_image_sha256"] != context.images[5]
                        || r.number("value")? != 1001
                        || r.number("data_counter")? != 0
                    {
                        return Err("negative initial App source/data differs".into());
                    }
                    self.work = Some(Work::new(r.number("actual_process")?));
                    self.stage = 3;
                }
            }
            3 => {
                if self.work.as_mut().unwrap().advance(serial, build, qmp)? {
                    if !cases::app_denials(&observed)? {
                        return Ok(());
                    }
                    qmp.set_running(false)?;
                    let captured: Result<()> = (|| {
                        let bytes = disk.bytes()?;
                        disk.capture(directory, "saved-before-test.raw")?;
                        self.baseline = Some(bytes);
                        Ok(())
                    })();
                    qmp.set_running(true)?;
                    captured?;
                    if self.goal == Goal::AppDenial {
                        self.begin_after(qmp)?;
                    } else {
                        self.send(
                            input,
                            if self.goal == Goal::Destination {
                                "net-destination\n"
                            } else {
                                "net-pending\n"
                            },
                        )?;
                        self.stage = 4;
                    }
                }
            }
            4 => match self.goal {
                Goal::Destination => {
                    if cases::destination(&observed)?
                        && fixture.hello_completed == 2
                        && fixture.pending_accepted == 0
                    {
                        self.unchanged_before_append(qmp, disk, directory)?;
                        self.begin_after(qmp)?;
                    }
                }
                Goal::DriverStop | Goal::ServiceStop => {
                    if cases::pending(&observed)?
                        && fixture.pending_accepted == 1
                        && fixture.hello_completed == 1
                    {
                        self.send(
                            input,
                            if self.goal == Goal::DriverStop {
                                "net-driver-stop\n"
                            } else {
                                "net-service-stop\n"
                            },
                        )?;
                        self.stage = 5;
                    }
                }
                Goal::LinkLoss => {
                    if cases::pending(&observed)?
                        && fixture.pending_accepted == 1
                        && fixture.hello_completed == 1
                    {
                        self.link_loss = Some(link_loss::Capture::begin(
                            serial,
                            &observed,
                            fixture,
                            self.work.as_ref().unwrap().app,
                            qmp,
                        )?);
                        self.unchanged_before_append(qmp, disk, directory)?;
                        self.begin_after(qmp)?;
                    }
                }
                _ => return Err("negative unsupported actual goal".into()),
            },
            5 => {
                if observed.iter().any(|r| r.kind == 6)
                    && observed.iter().any(|r| r.kind == 7)
                    && network
                        .iter()
                        .any(|p| p.stage == 7 && p.result == 0 && p.argument == 2)
                {
                    self.unchanged_before_append(qmp, disk, directory)?;
                    self.begin_after(qmp)?;
                }
            }
            6 => {
                if self.work.as_mut().unwrap().advance(serial, build, qmp)? {
                    self.send(input, "finish\n")?;
                    self.finish_sent = true;
                    self.stage = 7;
                }
            }
            7 => (),
            _ => return Err("negative Host stage".into()),
        }
        if let Some(work) = &self.work {
            let _ = note::app_step(serial, build, work.app)?;
        }
        Ok(())
    }
    fn begin_after(&mut self, qmp: &mut Qmp) -> Result<()> {
        self.work.as_mut().unwrap().append(qmp)?;
        self.stage = 6;
        Ok(())
    }
    fn unchanged_before_append(
        &self,
        qmp: &mut Qmp,
        disk: &storage::Disk,
        directory: &Path,
    ) -> Result<()> {
        qmp.set_running(false)?;
        let result = (|| {
            let actual = disk.bytes()?;
            disk.capture(directory, "after-test-before-later-edit.raw")?;
            if self.baseline.as_ref() != Some(&actual) {
                return Err("negative exercise changed saved disk before later Note edit".into());
            }
            Ok(())
        })();
        qmp.set_running(true)?;
        result
    }
    pub(super) fn verify_link_loss(
        &self,
        serial: &[u8],
        build: &str,
        qmp: &Qmp,
        fixture: &Snapshot,
    ) -> Result<()> {
        match (self.goal, &self.link_loss) {
            (Goal::LinkLoss, Some(capture)) => {
                capture.complete(serial, build, qmp.transcript(), fixture)
            }
            (Goal::LinkLoss, None) => Err("linkloss actual disconnect absent".into()),
            (_, Some(_)) => Err("unexpected network disconnect in original goal".into()),
            (_, None) => Ok(()),
        }
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"stage":self.stage,"finish_sent":self.finish_sent,"inputs":self.inputs,"captures":self.work.as_ref().map(|w|&w.captures),"app":self.work.as_ref().map(|w|w.app),"link_loss":self.link_loss})
    }
}
fn reply<'a>(
    rows: &'a [crate::native_protocol::StateRecord],
    op: &str,
) -> Result<Option<&'a crate::native_protocol::StateRecord>> {
    let rows: Vec<_> = rows.iter().filter(|r| r.fields["op"] == op).collect();
    if rows.len() > 1 {
        return Err(format!("negative command replay:{op}"));
    }
    if let Some(r) = rows.first() {
        if !r.is(op) || r.number("recovery")? != 0 {
            return Err(format!("negative command refused:{op}"));
        }
        Ok(Some(r))
    } else {
        Ok(None)
    }
}
fn actual_context(serial: &[u8], build: &str, context: &Context) -> Result<bool> {
    let mut common = false;
    for line in std::str::from_utf8(serial)
        .map_err(|_| "negative UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if common
                || c.mode != 0
                || c.root_image != context.images[0]
                || c.root_manifest != context.root_manifest
                || c.block_image != context.images[4]
                || c.root_frames != context.root_frames
                || c.block_frames != context.block_frames
            {
                return Err("negative actual Root/Block differs from selected source".into());
            }
            common = true;
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let crate::native3_protocol::Event::Critical(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if c.image != context.images[1] {
                return Err("negative actual Shell differs".into());
            }
        }
    }
    Ok(common)
}
