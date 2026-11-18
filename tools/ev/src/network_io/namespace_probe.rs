//! Owned disposable-VM namespace exercise and read-only disk authentication.
//! Local ROM provisioning is not remote release authorization or App execution.
use super::*;
use ev_content_store::{Area, Backend};
use ev_root_supervisor::{native_acquisition as acq, native_update as update};

#[derive(Default, serde::Serialize)]
pub(super) struct State {
    initialize_sent: bool,
    inspect_sent: bool,
    inputs: Vec<Value>,
}
impl State {
    /// Reconstruct completion from actual Root-origin records on every pass.
    /// A diagnostic alone never substitutes for the matching command reply.
    pub(super) fn next(&self, serial: &[u8], build: &str) -> Result<Option<&'static [u8]>> {
        let rows = crate::update_protocol::records(serial, build)?;
        let reports = crate::native_protocol::states(serial, build)?;
        let replies = |op: &str| -> Result<bool> {
            let found: Vec<_> = reports
                .iter()
                .filter(|r| r.fields.get("op").is_some_and(|v| v == op))
                .collect();
            if found.len() > 1 || found.first().is_some_and(|r| !r.is(op)) {
                return Err(format!("namespace command {op} refused or replayed"));
            }
            Ok(found.len() == 1)
        };
        let initialized = replies("update-init")?;
        let inspected = replies("update-inspect")?;
        if (!self.initialize_sent && (!rows.is_empty() || initialized))
            || (!self.inspect_sent && (inspected || rows.iter().any(|r| r.stage == 4)))
        {
            return Err("namespace work preceded its exact owned UART command".into());
        }
        let mut stage = 0;
        let mut previous = 0;
        for row in &rows {
            match row.stage {
                1 if stage == 0 => stage = 1,
                2 if stage == 1 && row.progress > previous => previous = row.progress,
                3 if stage == 1 => stage = 3,
                4 if stage == 3 && row.progress == 1 => stage = 4,
                5 => {
                    return Err(format!(
                        "actual namespace failure class={} progress={}",
                        row.result, row.progress
                    ));
                }
                _ => return Err("namespace progress missing, replayed or out of order".into()),
            }
        }
        if !self.initialize_sent {
            Ok(Some(b"update-init\n"))
        } else if initialized && stage >= 3 && !self.inspect_sent {
            Ok(Some(b"update-inspect\n"))
        } else if self.inspect_sent && inspected && stage == 4 {
            Ok(Some(b"finish\n"))
        } else {
            Ok(None)
        }
    }
    pub(super) fn sent(&mut self, request: &[u8], receipt: Value) {
        match request {
            b"update-init\n" => self.initialize_sent = true,
            b"update-inspect\n" => self.inspect_sent = true,
            _ => unreachable!("namespace observer command"),
        }
        self.inputs.push(receipt);
    }
    pub(super) fn complete(&self, serial: &[u8], build: &str) -> Result<bool> {
        Ok(self.next(serial, build)? == Some(b"finish\n".as_slice()))
    }
}

struct ReadOnlyDisk<'a> {
    bytes: &'a [u8],
    reads: u64,
}
struct Device<'a, 'b> {
    owner: &'a mut ReadOnlyDisk<'b>,
    start: u64,
    sectors: u64,
}
impl<'b> Backend for ReadOnlyDisk<'b> {
    type Error = &'static str;
    type Device<'a>
        = Device<'a, 'b>
    where
        Self: 'a;
    fn device(&mut self, area: Area) -> Self::Device<'_> {
        let (start, sectors) = match area {
            Area::Checkpoint => (128, ev_store::REQUIRED_SECTORS),
            Area::Objects => (256, ev_content_store::OBJECT_SECTORS),
        };
        Device {
            owner: self,
            start,
            sectors,
        }
    }
    fn has_unresolved_io(&self) -> bool {
        false
    }
}
impl ev_store::SectorIo for Device<'_, '_> {
    type Error = &'static str;
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut ev_store::Sector,
        cut: u64,
    ) -> std::result::Result<(), Self::Error> {
        if lba >= self.sectors || cut == 0 || cut == u64::MAX {
            return Err("read-only audit geometry/cut");
        }
        let start = usize::try_from((self.start + lba) * 512).map_err(|_| "audit offset")?;
        out.copy_from_slice(
            self.owner
                .bytes
                .get(start..start + 512)
                .ok_or("audit disk bound")?,
        );
        self.owner.reads += 1;
        Ok(())
    }
    fn write(
        &mut self,
        _: u64,
        _: &ev_store::Sector,
        _: u64,
    ) -> std::result::Result<(), Self::Error> {
        Err("read-only namespace audit forbids writes")
    }
    fn flush(&mut self, _: u64) -> std::result::Result<(), Self::Error> {
        Err("read-only namespace audit forbids flushes")
    }
}
/// Run the production cold verifier against exact captured disk bytes, with
/// writes physically unavailable. This proves local state, never fresh UTC.
pub(crate) fn disk(before: &[u8], after: &[u8]) -> Result<Value> {
    if before.len() != 4 * 1024 * 1024 || after.len() != before.len() {
        return Err("namespace probe requires exact4MiB captures".into());
    }
    let mut changed = Vec::new();
    for (sector, (a, b)) in before
        .as_chunks::<512>()
        .0
        .iter()
        .zip(after.as_chunks::<512>().0.iter())
        .enumerate()
    {
        if a != b {
            if !(128..142).contains(&sector) && !(256..8192).contains(&sector) {
                return Err(format!("namespace probe changed unrelated sector {sector}"));
            }
            changed.push(sector);
        }
    }
    if changed.is_empty() {
        return Err("namespace probe did not publish durable bytes".into());
    }
    let backend = ReadOnlyDisk {
        bytes: after,
        reads: 0,
    };
    let mut engine = update::Update::new();
    let mut buffers = acq::Buffers::empty();
    engine
        .begin(backend, update::Command::Inspect, 1)
        .map_err(|_| "audit begin refused")?;
    for tick in 2..4096 {
        if !engine.active() {
            break;
        }
        engine.step(&mut buffers, tick);
        engine.observe_after(tick);
    }
    let summary = match engine.outcome() {
        Some(update::Outcome::Complete(s))
            if s == (update::Summary {
                revision: 1,
                utc_floor: 0,
                candidate: 0,
                active: 0,
                known_good: 0,
            }) =>
        {
            s
        }
        other => {
            return Err(format!(
                "namespace captured bytes failed initial-ROM cold authentication: {other:?}"
            ));
        }
    };
    let backend = engine
        .take_completed()
        .ok_or("cold audit retained unresolved owner")?;
    use sha2::{Digest, Sha256};
    let disk_hash = format!("{:x}", Sha256::digest(after));
    Ok(
        json!({"schema":1,"kind":"read-only-production-cold-authentication","changed_sectors":changed,"unrelated_sectors_unchanged":true,"disk_sha256":disk_hash,"reads":backend.reads,"revision":summary.revision,"utc_floor":summary.utc_floor,"candidate":summary.candidate,"active":summary.active,"known_good":summary.known_good,"qualified_UTC_claim":false,"remote_authorization_claim":false,"App_execution_claim":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn progress(stage: u64, value: u64) -> String {
        format!(
            "EVROSION_M6_UPDATE_PROGRESS protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={} tick={} stage={stage} result=0 progress={value}\n",
            super::super::tests::build(),
            500 + stage,
            2000 + stage
        )
    }
    fn report(op: &str, index: u64) -> String {
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={} report={index} op={op} result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true\n",
            super::super::tests::build(),
            "0".repeat(64)
        )
    }
    #[test]
    fn each_next_command_needs_its_actual_completion_and_no_command_is_replayed() {
        let build = super::super::tests::build();
        let mut serial = super::super::tests::ready(&super::super::tests::context());
        let mut state = State::default();
        state.sent(b"update-init\n", json!({"test":"parser model only"}));
        serial.push_str(&progress(1, 0));
        assert_eq!(state.next(serial.as_bytes(), &build).unwrap(), None);
        serial.push_str(&progress(3, 7950));
        assert_eq!(state.next(serial.as_bytes(), &build).unwrap(), None);
        serial.push_str(&report("update-init", 1));
        assert_eq!(
            state.next(serial.as_bytes(), &build).unwrap(),
            Some(b"update-inspect\n".as_slice())
        );
        let inspect = progress(4, 1) + &report("update-inspect", 2);
        assert!(
            state
                .next(format!("{serial}{inspect}").as_bytes(), &build)
                .is_err()
        );
        state.sent(b"update-inspect\n", json!({"test":"parser model only"}));
        assert_eq!(state.next(serial.as_bytes(), &build).unwrap(), None);
        serial.push_str(&inspect);
        assert!(state.complete(serial.as_bytes(), &build).unwrap());
        assert!(
            state
                .next(
                    format!("{serial}{}", report("update-inspect", 3)).as_bytes(),
                    &build
                )
                .is_err()
        );
        assert!(
            state
                .next(
                    serial
                        .replace(
                            "op=update-inspect result=ok",
                            "op=update-inspect result=refused"
                        )
                        .as_bytes(),
                    &build
                )
                .is_err()
        );
    }
    struct Memory(Vec<u8>);
    struct MemDevice<'a> {
        owner: &'a mut Memory,
        start: u64,
        sectors: u64,
    }
    impl Backend for Memory {
        type Error = &'static str;
        type Device<'a> = MemDevice<'a>;
        fn device(&mut self, area: Area) -> Self::Device<'_> {
            let (start, sectors) = match area {
                Area::Checkpoint => (128, ev_store::REQUIRED_SECTORS),
                Area::Objects => (256, ev_content_store::OBJECT_SECTORS),
            };
            MemDevice {
                owner: self,
                start,
                sectors,
            }
        }
        fn has_unresolved_io(&self) -> bool {
            false
        }
    }
    impl ev_store::SectorIo for MemDevice<'_> {
        type Error = &'static str;
        fn sectors(&self) -> u64 {
            self.sectors
        }
        fn read(
            &mut self,
            lba: u64,
            out: &mut ev_store::Sector,
            _: u64,
        ) -> std::result::Result<(), Self::Error> {
            if lba >= self.sectors {
                return Err("read bound");
            }
            let start = ((self.start + lba) * 512) as usize;
            out.copy_from_slice(&self.owner.0[start..start + 512]);
            Ok(())
        }
        fn write(
            &mut self,
            lba: u64,
            bytes: &ev_store::Sector,
            _: u64,
        ) -> std::result::Result<(), Self::Error> {
            if lba >= self.sectors {
                return Err("write bound");
            }
            let start = ((self.start + lba) * 512) as usize;
            self.owner.0[start..start + 512].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
    }
    #[test]
    fn exact_production_initial_checkpoint_is_cold_authenticated_without_writes() {
        let before = vec![0; 4 * 1024 * 1024];
        let mut engine = update::Update::new();
        let mut buffers = acq::Buffers::empty();
        assert!(
            engine
                .begin(Memory(before.clone()), update::Command::Initialize, 1)
                .is_ok()
        );
        for tick in 2..16384 {
            if !engine.active() {
                break;
            }
            engine.step(&mut buffers, tick);
            engine.observe_after(tick);
        }
        assert!(
            matches!(engine.outcome(), Some(update::Outcome::Complete(_))),
            "{:?}",
            engine.outcome()
        );
        let mut after = engine.take_completed().unwrap().0;
        let checked = disk(&before, &after).unwrap();
        assert_eq!(checked["revision"], 1);
        assert_eq!(checked["utc_floor"], 0);
        assert!(checked["reads"].as_u64().unwrap() > 0);
        after[257 * 512] ^= 1;
        assert!(disk(&before, &after).is_err());
    }
    #[test]
    fn unrelated_disk_writes_and_diagnostics_without_owned_request_are_refused() {
        let blank = vec![0; 4 * 1024 * 1024];
        let mut changed = blank.clone();
        changed[512] = 1;
        assert!(
            disk(&blank, &changed)
                .unwrap_err()
                .contains("unrelated sector")
        );
        assert!(disk(&blank, &blank).is_err());
        let state = State::default();
        let build = super::super::tests::build();
        assert_eq!(
            state.next(&[], &build).unwrap(),
            Some(b"update-init\n".as_slice())
        );
        let serial = format!(
            "{}EVROSION_M6_UPDATE_PROGRESS protocol=1 build={build} root_process=1 root_thread=11 endpoint=7 ticket=500 tick=2000 stage=1 result=0 progress=0\n",
            super::super::tests::ready(&super::super::tests::context())
        );
        assert!(state.next(serial.as_bytes(), &build).is_err());
    }
}
