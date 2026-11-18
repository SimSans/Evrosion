//! Evidence for one guest initiated reset followed by an actual fresh boot.
//! Host reset commands, a reset request alone, or an old desktop cannot pass.
use serde::Serialize;
use serde_json::Value;

const SELECTED: &str = "EVROSION_M8_KERNEL_RUN phase=selected ";
const POWER: &str = "EVROSION_M8_SESSION_POWER phase=checked_restart ";
const ENDED: &str = "EVROSION_M8_KERNEL_RUN phase=ended ";
const ADAPTER: &str = "EVROSION_M8_SESSION_POWER phase=platform_restart_requested adapter=q35_ich9 port=0x0cf9 value=0x0f actual_second_boot_required=true";

#[derive(Debug, Clone, Serialize)]
pub(super) struct Witness {
    pub checked_restart_line: usize,
    pub first_ended_line: usize,
    pub adapter_line: usize,
    pub second_selected_line: usize,
    pub guest_reset_events: usize,
    pub first_boot_token: u64,
    pub first_boot_tick: u64,
    pub build: String,
}
#[derive(Debug, Clone, Serialize)]
pub(super) struct DialogReady {
    pub nonce: u64,
    pub frame: u64,
    pub barrier: u32,
    pub main_held: bool,
    pub keypad_held: bool,
    pub main_released: bool,
    pub keypad_released: bool,
    pub pointer_held: u8,
    pub pointer_released: u8,
    pub root_process: u64,
    pub root_thread: u64,
    pub record: String,
}
impl DialogReady {
    pub fn permits_main_enter(&self) -> bool {
        self.main_released && !self.main_held && !self.keypad_held
    }
}
/// A trusted Root diagnostic paces physical test input only. It never proves
/// consent, authority, a successful power operation, or human approval.
pub(super) fn dialog_ready(
    bytes: &[u8],
    build: &str,
    restart: bool,
    previous: Option<u64>,
) -> Result<Option<DialogReady>, String> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("power readiness serial exceeds bound".into());
    }
    let serial = core::str::from_utf8(bytes).map_err(|_| "power readiness serial is not UTF8")?;
    let serial = &serial[..serial.rfind('\n').map_or(0, |at| at + 1)];
    let lines: Vec<_> = serial.lines().collect();
    let Some(selected) = lines.iter().rposition(|l| l.starts_with(SELECTED)) else {
        return Ok(None);
    };
    if lines[selected]
        != format!("{SELECTED}build={build} actual_bundle=true legacy_root_cast=false")
    {
        return Err("power readiness selected build differs".into());
    }
    let Some(line) = lines[selected + 1..]
        .iter()
        .rev()
        .find(|l| l.starts_with("EVROSION_M8_POWER_DIALOG "))
    else {
        return Ok(None);
    };
    let p: Vec<_> = line.split(' ').collect();
    if p.len() != 16
        || p[1] != "phase=armed"
        || p[2] != format!("build={build}")
        || p[15] != "scope=trusted_root_pacing_only"
    {
        return Err("power readiness record shape differs".into());
    }
    let actual_restart = match p[3] {
        "intent=shutdown" => false,
        "intent=restart" => true,
        _ => return Err("power readiness intent differs".into()),
    };
    let boolean = |field: &str, key: &str| match field.strip_prefix(key) {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        _ => Err("power readiness boolean differs".to_string()),
    };
    let nonce = number(p[4], "nonce=")?;
    let frame = number(p[5], "frame=")?;
    let barrier = number(p[6], "barrier=")?;
    let pointer_held = number(p[11], "pointer_held=")?;
    let pointer_released = number(p[12], "pointer_released=")?;
    let process = number(p[13], "root_process=")?;
    let thread = number(p[14], "root_thread=")?;
    if [nonce, frame, process, thread]
        .iter()
        .any(|v| matches!(*v, 0 | u64::MAX))
        || barrier >= u32::MAX as u64
        || pointer_held > 7
        || pointer_released > 7
    {
        return Err("power readiness reserved metadata".into());
    }
    let ready = DialogReady {
        nonce,
        frame,
        barrier: barrier as u32,
        main_held: boolean(p[7], "main_held=")?,
        keypad_held: boolean(p[8], "keypad_held=")?,
        main_released: boolean(p[9], "main_released=")?,
        keypad_released: boolean(p[10], "keypad_released=")?,
        pointer_held: pointer_held as u8,
        pointer_released: pointer_released as u8,
        root_process: process,
        root_thread: thread,
        record: (*line).into(),
    };
    if actual_restart != restart || previous == Some(nonce) {
        return Ok(None);
    }
    Ok(Some(ready))
}

fn number(field: &str, key: &str) -> Result<u64, String> {
    let raw = field.strip_prefix(key).ok_or("restart field key differs")?;
    let value = raw
        .parse::<u64>()
        .map_err(|_| "restart counter is not u64")?;
    if value.to_string() != raw {
        return Err("restart counter is not canonical decimal".into());
    }
    Ok(value)
}

/// Incomplete observation returns None under the caller's original bounded
/// deadline. Contradictory records fail immediately, with all evidence retained.
pub(super) fn observe(
    bytes: &[u8],
    transcript: &[Value],
    expected_build: &str,
) -> Result<Option<Witness>, String> {
    let serial = core::str::from_utf8(bytes).map_err(|_| "restart serial is not UTF8")?;
    // Serial writes may be observed between two bytes of a record. Wait for
    // its actual newline instead of treating a partial selected marker as bad.
    let serial = &serial[..serial.rfind('\n').map_or(0, |at| at + 1)];
    let lines: Vec<_> = serial.lines().collect();
    let matching = |prefix: &str| {
        lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| l.starts_with(prefix).then_some(i))
            .collect::<Vec<_>>()
    };
    if transcript
        .iter()
        .any(|entry| entry["sent"]["execute"] == "system_reset")
    {
        return Err("host system_reset cannot prove guest restart".into());
    }
    let resets: Vec<_> = transcript
        .iter()
        .filter_map(|entry| {
            let event = &entry["received"];
            (event["event"] == "RESET" && event["data"]["guest"] == true).then_some(event)
        })
        .collect();
    if resets.len() > 1 || resets.iter().any(|e| e["data"]["reason"] != "guest-reset") {
        return Err("restart requires exactly one Q35 guest-reset event".into());
    }
    let selected = matching(SELECTED);
    if selected.len() > 2
        || selected.iter().any(|i| {
            lines[*i]
                != format!(
                    "{SELECTED}build={expected_build} actual_bundle=true legacy_root_cast=false"
                )
        })
    {
        return Err("restart selected build count or identity differs".into());
    }
    let power = matching(POWER);
    let adapters = matching("EVROSION_M8_SESSION_POWER phase=platform_restart_requested");
    if power.len() > 1 || adapters.len() > 1 || adapters.iter().any(|i| lines[*i] != ADAPTER) {
        return Err("restart request is duplicated or noncanonical".into());
    }
    if selected.len() < 2 || resets.len() != 1 || power.len() != 1 || adapters.len() != 1 {
        return Ok(None);
    }
    let ended = matching(ENDED);
    let before_second: Vec<_> = ended.into_iter().filter(|i| *i < selected[1]).collect();
    if before_second.len() != 1
        || !(selected[0] < power[0]
            && power[0] < before_second[0]
            && before_second[0] < adapters[0]
            && adapters[0] < selected[1])
    {
        return Err(
            "checked restart, first completion, adapter and fresh boot order differs".into(),
        );
    }
    let p: Vec<_> = lines[power[0]].split(' ').collect();
    let e: Vec<_> = lines[before_second[0]].split(' ').collect();
    if p.len() != 9
        || p[4..]
            != [
                "rpc=0",
                "windows=0",
                "async_debt=0",
                "physical_proof=trusted_root_flush_stop_scrub",
                "sources_retained_until_power=true",
            ]
        || e.len() != 9
        || e[2] != "root_exited=false"
        || e[6..]
            != [
                "retained=true",
                "scope=execution_only",
                "clean_shutdown=false",
            ]
    {
        return Err("restart checked physical/debt/completion fields differ".into());
    }
    let token = number(p[2], "token=")?;
    if matches!(token, 0 | u64::MAX) || number(e[3], "starts=")? == 0 {
        return Err("restart token or actual actor starts are reserved".into());
    }
    let _calls = number(e[4], "calls=")?;
    let _replies = number(e[5], "replies=")?;
    Ok(Some(Witness {
        checked_restart_line: power[0],
        first_ended_line: before_second[0],
        adapter_line: adapters[0],
        second_selected_line: selected[1],
        guest_reset_events: resets.len(),
        first_boot_token: token,
        first_boot_tick: number(p[3], "tick=")?,
        build: expected_build.into(),
    }))
}

pub(super) fn second_boot_bytes(bytes: &[u8]) -> Result<&[u8], String> {
    let serial = core::str::from_utf8(bytes).map_err(|_| "restart serial is not UTF8")?;
    let offsets: Vec<_> = serial.match_indices(SELECTED).map(|(at, _)| at).collect();
    if offsets.len() != 2 || offsets.iter().any(|at| *at != 0 && bytes[*at - 1] != b'\n') {
        return Err("restart requires exactly two complete selected records".into());
    }
    Ok(&bytes[offsets[1]..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn ready_pacing_requires_current_boot_new_nonce_and_actual_prior_break_knowledge() {
        let selected =
            format!("{SELECTED}build=m8-abc actual_bundle=true legacy_root_cast=false\n");
        let record = "EVROSION_M8_POWER_DIALOG phase=armed build=m8-abc intent=shutdown nonce=7 frame=9 barrier=17 main_held=false keypad_held=false main_released=true keypad_released=false pointer_held=0 pointer_released=1 root_process=5 root_thread=6 scope=trusted_root_pacing_only\n";
        let serial = selected.clone() + record;
        let ready = dialog_ready(serial.as_bytes(), "m8-abc", false, None)
            .unwrap()
            .unwrap();
        assert!(ready.permits_main_enter());
        assert!(
            dialog_ready(serial.as_bytes(), "m8-abc", false, Some(7))
                .unwrap()
                .is_none()
        );
        assert!(
            dialog_ready(serial.as_bytes(), "m8-abc", true, None)
                .unwrap()
                .is_none()
        );
        for changed in [
            serial.replace("main_held=false", "main_held=true"),
            serial.replace("main_released=true", "main_released=false"),
        ] {
            assert!(
                !dialog_ready(changed.as_bytes(), "m8-abc", false, None)
                    .unwrap()
                    .unwrap()
                    .permits_main_enter()
            );
        }
        let second = serial.clone() + &selected;
        assert!(
            dialog_ready(second.as_bytes(), "m8-abc", false, None)
                .unwrap()
                .is_none()
        );
        assert!(
            dialog_ready(serial.trim_end().as_bytes(), "m8-abc", false, None)
                .unwrap()
                .is_none()
        );
        for changed in [
            serial.replace("nonce=7", "nonce=0"),
            serial.replace("frame=9", "frame=09"),
            serial.replace("pointer_held=0", "pointer_held=8"),
            serial.replace("scope=trusted_root_pacing_only", "scope=consent"),
        ] {
            assert!(dialog_ready(changed.as_bytes(), "m8-abc", false, None).is_err());
        }
    }
    fn serial() -> String {
        format!(
            "{SELECTED}build=m8-abc actual_bundle=true legacy_root_cast=false\n{POWER}token=1 tick=100 rpc=0 windows=0 async_debt=0 physical_proof=trusted_root_flush_stop_scrub sources_retained_until_power=true\n{ENDED}root_exited=false starts=11 calls=100 replies=100 retained=true scope=execution_only clean_shutdown=false\n{ADAPTER}\n{SELECTED}build=m8-abc actual_bundle=true legacy_root_cast=false\n"
        )
    }
    fn event() -> Value {
        json!({"received":{"event":"RESET","data":{"guest":true,"reason":"guest-reset"}}})
    }
    #[test]
    fn checked_guest_reset_and_fresh_same_build_are_all_required() {
        let text = serial();
        let events = vec![event()];
        let witness = observe(text.as_bytes(), &events, "m8-abc")
            .unwrap()
            .unwrap();
        assert_eq!(witness.first_boot_token, 1);
        assert!(observe(text.as_bytes(), &[], "m8-abc").unwrap().is_none());
        assert!(observe(text.as_bytes(), &events, "m8-other").is_err());
        let first = text.rfind(SELECTED).unwrap();
        assert!(
            observe(&text.as_bytes()[..first], &events, "m8-abc")
                .unwrap()
                .is_none()
        );
        assert!(second_boot_bytes(&text.as_bytes()[..first]).is_err());
        let partial = format!("{}{SELECTED}build=m8-", &text[..first]);
        assert!(
            observe(partial.as_bytes(), &events, "m8-abc")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            second_boot_bytes(text.as_bytes()).unwrap(),
            &text.as_bytes()[first..]
        );
        for broken in [
            text.replace("rpc=0", "rpc=1"),
            text.replace("tick=100", "tick=0100"),
            text.replace("clean_shutdown=false", "clean_shutdown=true"),
            text.replace("retained=true", "retained=false"),
            text.replace("token=1", "token=0"),
        ] {
            assert!(observe(broken.as_bytes(), &events, "m8-abc").is_err());
        }
        assert!(observe(text.as_bytes(), &[event(), event()], "m8-abc").is_err());
        assert!(
            observe(
                text.as_bytes(),
                &[event(), json!({"sent":{"execute":"system_reset"}})],
                "m8-abc"
            )
            .is_err()
        );
        let host_reset = json!({"received":{"event":"RESET","data":{"guest":false,"reason":"host-qmp-system-reset"}}});
        assert!(
            observe(text.as_bytes(), &[host_reset], "m8-abc")
                .unwrap()
                .is_none()
        );
    }
}
