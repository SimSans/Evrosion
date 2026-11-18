//! Joins actual public relay bytes to Root's private verification diagnostic.
//! No invented clock/floor, chosen-nonce verifier or UTC qualification.
use super::*;
pub(super) fn complete(
    serial: &[u8],
    build: &str,
    s: &Snapshot,
    final_check: bool,
) -> Result<bool> {
    if s.exchanges
        .iter()
        .any(|exchange| exchange.mutation.is_some())
    {
        return Err("positive time goal observed a fault-injection witness".into());
    }
    let reports = crate::native_protocol::states(serial, build)?;
    let arms: Vec<_> = reports
        .iter()
        .filter(|s| s.fields.get("op").is_some_and(|op| op == "time-probe"))
        .collect();
    if arms.len() > 1 || arms.first().is_some_and(|s| !s.is("time-probe")) {
        return Err("actual owner time arm refused/replayed".into());
    }
    let proofs = crate::time_proof_protocol::records(serial, build)?;
    if let Some(p) = proofs.iter().find(|p| p.stage == 4) {
        return Err(format!(
            "actual unqualified time proof refused: class={} stage={}",
            p.result, p.argument
        ));
    }
    let Some(body_len) = transport(s, final_check)? else {
        return Ok(false);
    };
    let ready = arms.len() == 1
        && proofs.len() == 3
        && proofs[0].stage == 1
        && proofs[0].result == 0
        && proofs[0].argument == 1
        && proofs[1].stage == 2
        && proofs[1].result == 0
        && proofs[1].argument == body_len as u64
        && proofs[2].stage == 3
        && proofs[2].result == 0
        && proofs[2].argument == 11;
    // These are public transport bytes. Root's actual affine source path must
    // perform signature/nonce verification before emitting3. A valid-looking
    // body or diagnostic alone is never consumer Qualified time.
    if final_check && !ready {
        return Err("actual time proof never completed its private unqualified path".into());
    }
    Ok(ready)
}

pub(super) fn transport(s: &Snapshot, final_check: bool) -> Result<Option<usize>> {
    if s.omitted != 0
        || s.observed > 2
        || s.completed > s.observed
        || s.exchanges.len() != s.observed as usize
    {
        return Err("time fixture omitted/additional/inconsistent exchanges".into());
    }
    if let Some(first) = s.exchanges.first() {
        hello_exchange(first)?;
    }
    if s.observed < 2 {
        return if final_check {
            Err("time fixture incomplete".into())
        } else {
            Ok(None)
        };
    }
    let time = &s.exchanges[1];
    if s.completed != 2 || time.error.is_some() {
        return Err("actual time relay exchange failed".into());
    }
    const PREFIX: &[u8] = b"GET /time/";
    const SUFFIX: &[u8] = b" HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
    if time.request.len() != PREFIX.len() + 64 + SUFFIX.len()
        || !time.request.starts_with(PREFIX)
        || !time.request.ends_with(SUFFIX)
    {
        return Err("actual time request has unexpected nonce/path/headers".into());
    }
    let hex = &time.request[PREFIX.len()..PREFIX.len() + 64];
    if !hex
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || hex.iter().all(|b| *b == b'0')
    {
        return Err("actual time public challenge not canonical/nonzero".into());
    }
    let end = time
        .response
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("actual time HTTP header incomplete")?
        + 4;
    let body = &time.response[end..];
    let expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if time.response[..end] != *expected.as_bytes()
        || !(1..=ev_time_proof::MAX_REPLY_BYTES).contains(&body.len())
    {
        return Err("actual time relay not exact bounded HTTP200 response".into());
    }
    Ok(Some(body.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_fixture::Exchange;
    use crate::network_io::tests as model;
    fn proof(stage: u64, arg: u64) -> String {
        format!(
            "EVROSION_M6_TIME_PROOF protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={} tick={} stage={stage} result=0 argument={arg} utc=unqualified\n",
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
    fn fixture() -> Snapshot {
        // Retained public signed packet is only transport/model data here;
        // this Host validator does not create a guest challenge or UTC proof.
        let nonce = include_bytes!("../../../../libs/time-proof/tests/fixtures/nonce.bin");
        let packet = include_bytes!("../../../../libs/time-proof/tests/fixtures/response.bin");
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let mut s = model::exchange();
        s.observed = 2;
        s.completed = 2;
        s.exchanges.push(Exchange {request:format!("GET /time/{hex} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").into_bytes(),response:[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",packet.len()).as_bytes(),packet].concat(),error:None,mutation:None});
        s
    }
    #[test]
    fn time_goal_needs_own_arm_complete_private_diagnostic_and_exact_public_transport() {
        let text = model::ready(&model::context())
            + &arm()
            + &proof(1, 1)
            + &proof(2, 352)
            + &proof(3, 11);
        let s = fixture();
        assert!(complete(text.as_bytes(), &model::build(), &s, true).unwrap());
        assert!(
            !complete(
                text.replace(&proof(3, 11), "").as_bytes(),
                &model::build(),
                &s,
                false
            )
            .unwrap()
        );
        assert!(
            !complete(
                text.replace(&arm(), "").as_bytes(),
                &model::build(),
                &s,
                false
            )
            .unwrap()
        );
        assert!(!complete(text.as_bytes(), &model::build(), &model::exchange(), false).unwrap());
        assert!(complete(text.as_bytes(), &model::build(), &model::exchange(), true).is_err());
        assert!(
            complete(
                text.replace("op=time-probe result=ok", "op=time-probe result=busy")
                    .as_bytes(),
                &model::build(),
                &s,
                false
            )
            .is_err()
        );
        for change in 0..5 {
            let mut bad = s.clone();
            match change {
                0 => bad.exchanges[1].request[10] = b'G',
                1 => bad.exchanges[1].response[9] = b'5',
                2 => {
                    bad.exchanges[1].response.pop();
                }
                3 => bad.omitted = 1,
                _ => bad.exchanges[1].error = Some("actualpartialwrite".into()),
            }
            assert!(complete(text.as_bytes(), &model::build(), &bad, false).is_err());
        }
    }
}
