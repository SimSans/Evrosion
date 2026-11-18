//! Owned QMP pause and a fresh actual-Root check of the original private anchor.
//! The relative RTC comparison is a finite observation, never UTC qualification.
use super::*;

const PAUSE: Duration = Duration::from_secs(35);
#[derive(serde::Serialize)]
struct Bracket {
    before_ns: u64,
    after_ns: u64,
}
#[derive(Default, serde::Serialize)]
pub(super) struct State {
    baseline: Option<crate::time_protocol::Progress>,
    paused: Option<Bracket>,
    resumed: Option<Bracket>,
    check_input: Option<Value>,
    #[serde(skip)]
    paused_at: Option<Instant>,
}
fn elapsed(origin: Instant) -> Result<u64> {
    crate::perf_ledger::elapsed_ns(origin, Instant::now())
        .map_err(|e| format!("pause probe host clock: {e:?}"))
}
fn baseline(serial: &[u8], build: &str) -> Result<Option<crate::time_protocol::Progress>> {
    let proofs = crate::time_proof_protocol::records(serial, build)?;
    let Some(proof) = proofs.last().filter(|p| p.stage == 3 && p.result == 0) else {
        return Err("pause requires the actual completed original private time proof".into());
    };
    Ok(crate::time_protocol::records(serial, build)?
        .into_iter()
        .find(|p| {
            p.stage == 2
                && p.result == 0
                && p.tick > proof.tick
                && p.ticket > proof.ticket
                && p.root_process == proof.root_process
                && p.root_thread == proof.root_thread
                && p.endpoint == proof.endpoint
        }))
}
impl State {
    #[cfg(test)]
    pub(super) fn completed_model(serial: &[u8], build: &str) -> Self {
        // Synthetic Host brackets used only to exercise the actual validator.
        Self {
            baseline: baseline(serial, build).unwrap(),
            paused: Some(Bracket {
                before_ns: 10,
                after_ns: 20,
            }),
            resumed: Some(Bracket {
                before_ns: 35_000_000_020,
                after_ns: 35_000_000_030,
            }),
            check_input: Some(json!({"synthetic":"owned UART marker"})),
            paused_at: None,
        }
    }
    pub(super) fn check_sent(&self) -> bool {
        self.check_input.is_some()
    }
    /// One bounded watcher step. The35s wait never blocks serial/process/deadline
    /// observation; both QMP transitions require actual query-status confirmation.
    pub(super) fn advance(
        &mut self,
        serial: &[u8],
        build: &str,
        qmp: &mut Qmp,
        input: &mut impl Write,
        origin: Instant,
    ) -> Result<bool> {
        self.complete(serial, build, false)?;
        if self.paused.is_none() {
            let Some(base) = baseline(serial, build)? else {
                return Ok(false);
            };
            let before_ns = elapsed(origin)?;
            qmp.set_running(false)?;
            let after_ns = elapsed(origin)?;
            self.paused_at = Some(Instant::now());
            self.baseline = Some(base);
            self.paused = Some(Bracket {
                before_ns,
                after_ns,
            });
            return Ok(false);
        }
        if self.resumed.is_none() {
            if !pause_due(
                self.paused_at.ok_or("pause confirmation absent")?,
                Instant::now(),
            )? {
                return Ok(false);
            }
            let before_ns = elapsed(origin)?;
            qmp.set_running(true)?;
            let after_ns = elapsed(origin)?;
            self.resumed = Some(Bracket {
                before_ns,
                after_ns,
            });
            let before = elapsed(origin)?;
            input
                .write_all(b"time-check\n")
                .and_then(|()| input.flush())
                .map_err(|e| e.to_string())?;
            self.check_input = Some(
                json!({"device":"owned QEMU owner UART","bytes":"time-check\n","host_bracket_ns":[before,elapsed(origin)?],"scripted_input":true,"human_consent_claim":false}),
            );
            return Ok(false);
        }
        self.complete(serial, build, false)
    }
    pub(super) fn complete(&self, serial: &[u8], build: &str, final_check: bool) -> Result<bool> {
        let reports = crate::native_protocol::states(serial, build)?;
        let arms: Vec<_> = reports
            .iter()
            .filter(|s| s.fields.get("op").is_some_and(|op| op == "time-check"))
            .collect();
        let checks = crate::tc_protocol::records(serial, build)?;
        if arms.len() > 1 || arms.first().is_some_and(|s| !s.is("time-check")) {
            return Err("actual retained-anchor check refused/replayed".into());
        }
        if !self.check_sent() && (!arms.is_empty() || !checks.is_empty()) {
            return Err("retained-anchor check preceded its explicit owned UART request".into());
        }
        if arms.len() != 1 || checks.len() != 1 {
            return if final_check {
                Err("pause probe lacks its actual check/acknowledgment".into())
            } else {
                Ok(false)
            };
        }
        let base = self
            .baseline
            .as_ref()
            .ok_or("fresh post-proof RTC baseline absent")?;
        let paused = self
            .paused
            .as_ref()
            .ok_or("actual paused confirmation absent")?;
        let resumed = self
            .resumed
            .as_ref()
            .ok_or("actual running confirmation absent")?;
        if paused.before_ns > paused.after_ns
            || resumed.before_ns > resumed.after_ns
            || resumed
                .before_ns
                .checked_sub(paused.after_ns)
                .is_none_or(|n| n < PAUSE.as_nanos() as u64)
        {
            return Err("actual QMP pause bracket is not the required finite35s interval".into());
        }
        let actual = &checks[0];
        if actual.result != 2
            || actual.stage != 1
            || (actual.root_process, actual.root_thread, actual.endpoint)
                != (base.root_process, base.root_thread, base.endpoint)
            || actual.tick <= base.tick
            || actual.ticket <= base.ticket
            || actual
                .elapsed_seconds
                .checked_sub(base.elapsed_seconds)
                .is_none_or(|n| !(34..=36).contains(&n))
        {
            return Err(
                "actual retained-anchor check lacks Age expiry or35s±1 relative RTC advance".into(),
            );
        }
        // Rejoin the baseline to this exact serial's original TP3 and TM. No
        // cached pre-proof sample or replacement anchor can satisfy the check.
        if baseline(serial, build)?.is_none_or(|p| {
            p.ticket != base.ticket
                || p.tick != base.tick
                || p.elapsed_seconds != base.elapsed_seconds
        }) {
            return Err("pause baseline differs from original post-proof actual sample".into());
        }
        Ok(true)
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"state":self,"pause_seconds":35,"rtc_delta_seconds_allowed":[34,36],"scope":"Finite actual QMP pause, original private Anchor Age rejection and relative RTC observation. Neither UTC qualification nor calibrated clock rate."})
    }
}
fn pause_due(paused: Instant, now: Instant) -> Result<bool> {
    now.checked_duration_since(paused)
        .map(|n| n >= PAUSE)
        .ok_or_else(|| "pause probe host monotonic regression".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_io::tests as model;
    fn proof() -> String {
        (1..=3).map(|stage|format!("EVROSION_M6_TIME_PROOF protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={} tick={} stage={stage} result=0 argument={} utc=unqualified\n",model::build(),300+stage,2000+stage,if stage==3 {11}else{1})).collect()
    }
    fn tm(ticket: u64, tick: u64, seconds: u64) -> String {
        format!(
            "EVROSION_M6_TIME_PROGRESS protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={ticket} tick={tick} stage=2 result=0 elapsed_seconds={seconds}\n",
            model::build()
        )
    }
    fn check() -> String {
        format!(
            "EVROSION_M6_TIME_CHECK protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket=500 tick=6000 stage=1 result=2 elapsed_seconds=38 utc=unqualified\r\n",
            model::build()
        )
    }
    fn arm() -> String {
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={} report=1 op=time-check result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true\n",
            model::build(),
            "0".repeat(64)
        )
    }
    fn state(serial: &str) -> State {
        State {
            baseline: baseline(serial.as_bytes(), &model::build()).unwrap(),
            paused: Some(Bracket {
                before_ns: 10,
                after_ns: 20,
            }),
            resumed: Some(Bracket {
                before_ns: 35_000_000_020,
                after_ns: 35_000_000_030,
            }),
            check_input: Some(json!({"test":"synthetic actual-UART marker"})),
            paused_at: None,
        }
    }
    #[test]
    fn cached_preproof_sample_cannot_start_pause_and_wait_does_not_renew() {
        let before = model::ready(&model::context()) + &tm(302, 2002, 2) + &proof();
        assert!(
            baseline(before.as_bytes(), &model::build())
                .unwrap()
                .is_none()
        );
        let fresh = before + &tm(304, 2004, 3);
        assert_eq!(
            baseline(fresh.as_bytes(), &model::build())
                .unwrap()
                .unwrap()
                .elapsed_seconds,
            3
        );
        let at = Instant::now();
        assert!(!pause_due(at, at + Duration::from_millis(34_999)).unwrap());
        assert!(pause_due(at, at + Duration::from_secs(35)).unwrap());
        assert!(pause_due(at + Duration::from_secs(1), at).is_err());
    }
    #[test]
    fn age_requires_one_owned_check_actual_pause_and_exact_postproof_rtc_join() {
        let text = model::ready(&model::context()) + &proof() + &tm(304, 2004, 3);
        let s = state(&text);
        assert!(!s.complete(text.as_bytes(), &model::build(), false).unwrap());
        assert!(s.complete(text.as_bytes(), &model::build(), true).is_err());
        let good = text + &arm() + &check();
        assert!(s.complete(good.as_bytes(), &model::build(), true).unwrap());
        for bad in [
            good.replace("result=2 elapsed_seconds", "result=0 elapsed_seconds"),
            good.replace("elapsed_seconds=38", "elapsed_seconds=36"),
            good.replace("elapsed_seconds=38", "elapsed_seconds=40"),
            good.replace("ticket=500", "ticket=304"),
            good.replace("tick=6000", "tick=2004"),
            good.replace("op=time-check result=ok", "op=time-check result=busy"),
            good.clone() + &arm(),
            good.clone() + &check(),
            good.replace("tick=2004", "tick=2003"),
        ] {
            assert!(
                s.complete(bad.as_bytes(), &model::build(), true).is_err(),
                "{bad}"
            );
        }
        let mut short = state(&good);
        short.resumed.as_mut().unwrap().before_ns -= 1;
        assert!(
            short
                .complete(good.as_bytes(), &model::build(), true)
                .is_err()
        );
        let mut no_input = state(&good);
        no_input.check_input = None;
        assert!(
            no_input
                .complete(good.as_bytes(), &model::build(), true)
                .is_err()
        );
    }
}
