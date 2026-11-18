//! Two private proof generations on the same actual Root/Client. A confirmed
//! expiry never reopens the old Anchor; only a new challenge plus fresh TC0
//! can complete this route. Public signatures/transport grant no UTC authority.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Default, serde::Serialize)]
pub(super) struct State {
    original: time_pause::State,
    original_prefix_bytes: Option<usize>,
    original_prefix_sha256: Option<String>,
    refresh_input: Option<Value>,
    fresh_check_input: Option<Value>,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn send(input: &mut impl Write, bytes: &[u8], origin: Instant) -> Result<Value> {
    let before = crate::perf_ledger::elapsed_ns(origin, Instant::now())
        .map_err(|e| format!("refresh host clock: {e:?}"))?;
    input
        .write_all(bytes)
        .and_then(|()| input.flush())
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"device":"owned QEMU owner UART","bytes":std::str::from_utf8(bytes).unwrap(),"host_bracket_ns":[before,crate::perf_ledger::elapsed_ns(origin,Instant::now()).map_err(|e|format!("refresh host clock: {e:?}"))?],"scripted_input":true,"human_consent_claim":false}),
    )
}
fn transport(snapshot: &Snapshot, second: bool) -> Result<Option<Vec<u8>>> {
    let limit = if second { 3 } else { 2 };
    if snapshot.omitted != 0
        || snapshot.observed > limit
        || snapshot.completed > snapshot.observed
        || snapshot.exchanges.len() != snapshot.observed as usize
        || snapshot.exchanges.iter().any(|e| e.mutation.is_some())
    {
        return Err("refresh fixture counts/mutation/extra exchange".into());
    }
    if snapshot.observed < limit {
        return Ok(None);
    }
    if snapshot.completed != limit {
        return Err("refresh fixture exchange incomplete".into());
    }
    let first = Snapshot {
        observed: 2,
        completed: 2,
        omitted: 0,
        exchanges: snapshot.exchanges[..2].to_vec(),
    };
    time_probe::transport(&first, true)?;
    if !second {
        return Ok(Some(Vec::new()));
    }
    let pair = Snapshot {
        observed: 2,
        completed: 2,
        omitted: 0,
        exchanges: vec![snapshot.exchanges[0].clone(), snapshot.exchanges[2].clone()],
    };
    time_probe::transport(&pair, true)?;
    let old = &snapshot.exchanges[1];
    let new = &snapshot.exchanges[2];
    if old.request == new.request {
        return Err("refresh reused the old public challenge".into());
    }
    for exchange in [old, new] {
        let at = exchange
            .response
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .unwrap()
            + 4;
        crate::network_fixture::time_corruption::verify_original(&exchange.response[at..])?;
    }
    Ok(Some(new.request.clone()))
}
impl State {
    fn original_prefix<'a>(&self, serial: &'a [u8]) -> Result<Option<&'a [u8]>> {
        let Some(length) = self.original_prefix_bytes else {
            return Ok(None);
        };
        let prefix = serial
            .get(..length)
            .ok_or("original refresh history truncated")?;
        if self.original_prefix_sha256.as_deref() != Some(&digest(prefix)) {
            return Err("original refresh history changed".into());
        }
        Ok(Some(prefix))
    }
    pub(super) fn complete(
        &self,
        serial: &[u8],
        build: &str,
        snapshot: &Snapshot,
        final_check: bool,
    ) -> Result<bool> {
        let reports = crate::native_protocol::states(serial, build)?;
        let arms: Vec<_> = reports
            .iter()
            .filter(|r| r.fields.get("op").is_some_and(|v| v == "time-probe"))
            .collect();
        let checks: Vec<_> = reports
            .iter()
            .filter(|r| r.fields.get("op").is_some_and(|v| v == "time-check"))
            .collect();
        let allowed_arms = 1 + usize::from(self.refresh_input.is_some());
        let allowed_checks =
            usize::from(self.original.check_sent()) + usize::from(self.fresh_check_input.is_some());
        if arms.len() > allowed_arms
            || checks.len() > allowed_checks
            || arms.iter().any(|r| !r.is("time-probe"))
            || checks.iter().any(|r| !r.is("time-check"))
        {
            return Err("refresh command refused/replayed/unrequested".into());
        }
        let proofs = crate::time_proof_protocol::records(serial, build)?;
        if proofs.iter().any(|p| p.stage == 4)
            || !crate::te_protocol::records(serial, build)?.is_empty()
        {
            return Err("refresh private exchange failed".into());
        }
        let actual = crate::tc_protocol::records(serial, build)?;
        if actual.len() > allowed_checks
            || actual.first().is_some_and(|p| p.result != 2)
            || actual.get(1).is_some_and(|p| p.result != 0)
        {
            return Err("refresh check lacks original Age2/new fresh0".into());
        }
        let Some(prefix) = self.original_prefix(serial)? else {
            transport(snapshot, false)?;
            self.original.complete(serial, build, false)?;
            return if final_check {
                Err("refresh original expiry incomplete".into())
            } else {
                Ok(false)
            };
        };
        if !self.original.complete(prefix, build, true)?
            || !time_probe::complete(
                prefix,
                build,
                &Snapshot {
                    observed: 2,
                    completed: 2,
                    omitted: 0,
                    exchanges: snapshot
                        .exchanges
                        .get(..2)
                        .ok_or("original fixture disappeared")?
                        .to_vec(),
                },
                true,
            )?
        {
            return Err("refresh original proof/expiry changed".into());
        }
        let transported = transport(snapshot, self.refresh_input.is_some())?.is_some();
        if proofs.len() > 3
            && (proofs[3].stage != 1
                || proofs[3].argument != 2
                || actual
                    .first()
                    .is_none_or(|old| proofs[3].ticket <= old.ticket || proofs[3].tick < old.tick))
        {
            return Err("refresh lacks a new persistent sequence2 after expiry".into());
        }
        let ready = transported
            && arms.len() == 2
            && checks.len() == 2
            && proofs.len() == 4
            && actual.len() == 2
            && self.fresh_check_input.is_some()
            && actual[1].ticket > proofs[3].ticket
            && actual[1].tick > proofs[3].tick;
        if final_check && !ready {
            return Err("refresh lacks actual new-proof fresh check and command replies".into());
        }
        Ok(ready)
    }
    pub(super) fn advance(
        &mut self,
        serial: &[u8],
        build: &str,
        snapshot: &Snapshot,
        qmp: &mut Qmp,
        input: &mut impl Write,
        origin: Instant,
    ) -> Result<bool> {
        self.complete(serial, build, snapshot, false)?;
        if self.original_prefix_bytes.is_none() {
            if !time_probe::complete(serial, build, snapshot, false)? {
                return Ok(false);
            }
            if !self.original.advance(serial, build, qmp, input, origin)? {
                return Ok(false);
            }
            self.original_prefix_bytes = Some(serial.len());
            self.original_prefix_sha256 = Some(digest(serial));
            self.refresh_input = Some(send(input, b"time-probe\n", origin)?);
            return Ok(false);
        }
        if self.fresh_check_input.is_none()
            && transport(snapshot, true)?.is_some()
            && crate::time_proof_protocol::records(serial, build)?.len() == 4
        {
            self.fresh_check_input = Some(send(input, b"time-check\n", origin)?);
            return Ok(false);
        }
        self.complete(serial, build, snapshot, false)
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"state":self,"scope":"Original affine Anchor rejected as Age2 after confirmed35s; separately published distinct challenge/sequence2 and new actual fresh TC0. No reconstructed TP2/3 beyond lifetime4, UTC qualification or durable floor."})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_fixture::Exchange;
    use crate::network_io::tests as model;
    fn proof(ticket: u64, stage: u64, arg: u64) -> String {
        format!(
            "EVROSION_M6_TIME_PROOF protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={ticket} tick={} stage={stage} result=0 argument={arg} utc=unqualified\n",
            model::build(),
            ticket + 1700
        )
    }
    fn report(serial: u64, op: &str) -> String {
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={} report={serial} op={op} result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true\n",
            model::build(),
            "0".repeat(64)
        )
    }
    fn tc(ticket: u64, result: u64, elapsed: u64) -> String {
        format!(
            "EVROSION_M6_TIME_CHECK protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={ticket} tick={} stage=1 result={result} elapsed_seconds={elapsed} utc=unqualified\n",
            model::build(),
            ticket + 5500
        )
    }
    fn original() -> String {
        model::ready(&model::context())
            + &report(1, "time-probe")
            + &proof(301, 1, 1)
            + &proof(302, 2, 352)
            + &proof(303, 3, 11)
            + &format!(
                "EVROSION_M6_TIME_PROGRESS protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket=304 tick=2004 stage=2 result=0 elapsed_seconds=3\n",
                model::build()
            )
            + &tc(500, 2, 38)
            + &report(2, "time-check")
    }
    fn fixture() -> Snapshot {
        let packet = include_bytes!("../../../../libs/time-proof/tests/fixtures/response.bin");
        // Untrusted public packet and synthetic Root rows only. Host signature
        // checking does not verify a chosen nonce; the actual guest Client
        // must establish that binding before a real TC0 can exist.
        let nonce = include_bytes!("../../../../libs/time-proof/tests/fixtures/nonce.bin");
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let mut snapshot = model::exchange();
        for nonce in [hex, "42".repeat(32)] {
            snapshot.exchanges.push(Exchange{request:format!("GET /time/{nonce} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").into_bytes(),response:[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",packet.len()).as_bytes(),packet].concat(),error:None,mutation:None});
        }
        snapshot.observed = 3;
        snapshot.completed = 3;
        snapshot
    }
    fn state(prefix: &str) -> State {
        State {
            original: time_pause::State::completed_model(prefix.as_bytes(), &model::build()),
            original_prefix_bytes: Some(prefix.len()),
            original_prefix_sha256: Some(digest(prefix.as_bytes())),
            refresh_input: Some(json!({"synthetic":"second arm"})),
            fresh_check_input: Some(json!({"synthetic":"second check"})),
        }
    }
    #[test]
    fn refreshed_check_needs_new_nonce_sequence_and_actual_fresh_root_result() {
        let prefix = original();
        let state = state(&prefix);
        let fixture = fixture();
        let text = prefix.clone()
            + &report(3, "time-probe")
            + &proof(600, 1, 2).replace("tick=2300", "tick=6100")
            + &tc(700, 0, 39)
            + &report(4, "time-check");
        assert!(
            state
                .complete(text.as_bytes(), &model::build(), &fixture, true)
                .unwrap()
        );
        for bad in [
            text.replace(&report(3, "time-probe"), ""),
            text.replace(&report(4, "time-check"), ""),
            text.replace(
                "ticket=600 tick=6100 stage=1 result=0 argument=2",
                "ticket=600 tick=6100 stage=1 result=0 argument=1",
            ),
            text.replace(
                "ticket=700 tick=6200 stage=1 result=0",
                "ticket=700 tick=6200 stage=1 result=2",
            ),
            text.replace("op=time-check result=ok", "op=time-check result=refused"),
            text.clone() + &tc(800, 0, 40),
            text.replace("elapsed_seconds=3\n", "elapsed_seconds=4\n"),
        ] {
            assert!(
                state
                    .complete(bad.as_bytes(), &model::build(), &fixture, true)
                    .is_err()
            );
        }
        let mut replay = fixture.clone();
        replay.exchanges[2] = replay.exchanges[1].clone();
        assert!(
            state
                .complete(text.as_bytes(), &model::build(), &replay, true)
                .is_err()
        );
        let mut corrupt = fixture.clone();
        let body = corrupt.exchanges[2]
            .response
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .unwrap()
            + 4;
        // Mutate actual SIG64. The public INDX/nonce-Merkle binding belongs
        // to the private guest verifier and is not a Host-created proof.
        corrupt.exchanges[2].response[body + 60] ^= 1;
        assert!(
            state
                .complete(text.as_bytes(), &model::build(), &corrupt, true)
                .is_err()
        );
        let mut truncated = text.clone();
        truncated.truncate(prefix.len() + report(3, "time-probe").len());
        assert!(
            !state
                .complete(truncated.as_bytes(), &model::build(), &fixture, false)
                .unwrap()
        );
        assert!(
            state
                .complete(truncated.as_bytes(), &model::build(), &fixture, true)
                .is_err()
        );
    }
}
