//! Expected source refusal is distinct from complete checked VM retirement.
use super::*;
pub(super) fn no_time(serial: &[u8], build: &str) -> Result<()> {
    if !crate::time_proof_protocol::records(serial, build)?.is_empty()
        || !crate::tc_protocol::records(serial, build)?.is_empty()
        || !crate::te_protocol::records(serial, build)?.is_empty()
    {
        return Err("missing-entropy route unexpectedly performed time work".into());
    }
    Ok(())
}
pub(super) fn empty_fixture(s: &Snapshot) -> Result<bool> {
    if s.observed != 0 || s.completed != 0 || s.omitted != 0 || !s.exchanges.is_empty() {
        return Err("missing entropy unexpectedly reached network fixture".into());
    }
    Ok(true)
}
pub(super) fn corrupt(serial: &[u8], build: &str, s: &Snapshot, final_check: bool) -> Result<bool> {
    if !crate::tc_protocol::records(serial, build)?.is_empty() {
        return Err("corrupt proof unexpectedly yielded a retained-anchor check".into());
    }
    let reports = crate::native_protocol::states(serial, build)?;
    let arms: Vec<_> = reports
        .iter()
        .filter(|s| s.fields.get("op").is_some_and(|op| op == "time-probe"))
        .collect();
    if arms.len() > 1 || arms.first().is_some_and(|s| !s.is("time-probe")) {
        return Err("corrupt-time owner arm refused/replayed".into());
    }
    let proofs = crate::time_proof_protocol::records(serial, build)?;
    if proofs
        .iter()
        .any(|p| p.stage == 3 || p.stage == 4 && (p.result != 4 || p.argument != 3))
    {
        return Err("corrupt-time route lacks the expected private Proof refusal".into());
    }
    let Some(length) = time_probe::transport(s, final_check)? else {
        return Ok(false);
    };
    if s.exchanges[0].mutation.is_some() {
        return Err("Hello was modified during signature fault injection".into());
    }
    let exchange = &s.exchanges[1];
    let mutation = exchange
        .mutation
        .as_ref()
        .ok_or("corrupt-time mutation witness absent")?;
    if crate::network_fixture::time_corruption::checked(&mutation.original)? != *mutation {
        return Err("corrupt-time original/mutated signature witness differs".into());
    }
    let end = exchange
        .response
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .unwrap()
        + 4;
    if length != mutation.mutated.len() || exchange.response[end..] != mutation.mutated {
        return Err("actual written HTTP bytes differ from signature mutation witness".into());
    }
    let ready = arms.len() == 1
        && proofs.len() == 3
        && proofs[0].stage == 1
        && proofs[0].result == 0
        && proofs[0].argument == 1
        && proofs[1].stage == 2
        && proofs[1].result == 0
        && proofs[1].argument == length as u64
        && proofs[2].stage == 4
        && proofs[2].result == 4
        && proofs[2].argument == 3;
    if final_check && !ready {
        return Err("actual private corrupt-proof refusal incomplete".into());
    }
    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_fixture::{Exchange, time_corruption};
    use crate::network_io::tests as model;

    fn proof(stage: u64, result: u64, argument: u64) -> String {
        format!(
            "EVROSION_M6_TIME_PROOF protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={} tick={} stage={stage} result={result} argument={argument} utc=unqualified\n",
            model::build(),
            300 + stage,
            2000 + stage
        )
    }
    fn arm() -> String {
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={} report=1 op=time-probe result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true\n",
            model::build(),
            "0".repeat(64)
        )
    }
    fn signed_fixture() -> Snapshot {
        let nonce = include_bytes!("../../../../libs/time-proof/tests/fixtures/nonce.bin");
        let original = include_bytes!("../../../../libs/time-proof/tests/fixtures/response.bin");
        let mutation = time_corruption::checked(original).unwrap();
        let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let mut snapshot = model::exchange();
        snapshot.observed = 2;
        snapshot.completed = 2;
        snapshot.exchanges.push(Exchange{
            request:format!("GET /time/{nonce} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").into_bytes(),
            response:[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",mutation.mutated.len()).as_bytes(),&mutation.mutated].concat(),
            error:None,mutation:Some(mutation),
        });
        snapshot
    }
    #[test]
    fn signature_negative_requires_actual_proof_refusal_and_exact_written_mutation() {
        let fixture = signed_fixture();
        let prefix = model::ready(&model::context()) + &arm() + &proof(1, 0, 1) + &proof(2, 0, 352);
        let good = prefix.clone() + &proof(4, 4, 3);
        assert!(corrupt(good.as_bytes(), &model::build(), &fixture, true).unwrap());
        assert!(!corrupt(prefix.as_bytes(), &model::build(), &fixture, false).unwrap());
        assert!(corrupt(prefix.as_bytes(), &model::build(), &fixture, true).is_err());
        assert!(time_probe::complete(good.as_bytes(), &model::build(), &fixture, false).is_err());
        for bad in [
            prefix.clone() + &proof(3, 0, 11),
            prefix.clone() + &proof(4, 3, 3),
            prefix + &proof(4, 4, 2),
            good.replace(&arm(), ""),
            good.replace(
                "root_process=1 root_thread=11 endpoint=7 ticket=304",
                "root_process=2 root_thread=11 endpoint=7 ticket=304",
            ),
        ] {
            assert!(corrupt(bad.as_bytes(), &model::build(), &fixture, true).is_err());
        }
        for change in 0..6 {
            let mut bad = fixture.clone();
            match change {
                0 => bad.exchanges[1].mutation = None,
                1 => bad.exchanges[1].mutation.as_mut().unwrap().bit_mask = 2,
                2 => bad.exchanges[1].mutation.as_mut().unwrap().mutated[80] ^= 1,
                3 => *bad.exchanges[1].response.last_mut().unwrap() ^= 1,
                4 => bad.completed = 1,
                _ => bad.omitted = 1,
            }
            assert!(
                corrupt(good.as_bytes(), &model::build(), &bad, true).is_err(),
                "change{change}"
            );
        }
    }
    #[test]
    fn absent_entropy_requires_no_time_or_network_transport_evidence() {
        assert!(empty_fixture(&Snapshot::default()).unwrap());
        assert!(empty_fixture(&model::exchange()).is_err());
        let prefix = model::ready(&model::context());
        no_time(prefix.as_bytes(), &model::build()).unwrap();
        assert!(no_time((prefix + &proof(4, 1, 1)).as_bytes(), &model::build()).is_err());
    }
}
