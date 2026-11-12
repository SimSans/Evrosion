//! Diagnostics for one explicit provider replacement fixture. These records are
//! accepted only with the independently retained source/ELF/manifest binding.
use crate::{boot_protocol::canonical_number as number, build::Result};
use ev_userspace_contract::provider as wire;
use serde::Serialize;
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Images {
    pub root: [u8; 32],
    pub consumer: [u8; 32],
    pub a: [u8; 32],
    pub b: [u8; 32],
}
fn hex<const N: usize>(field: &str, key: &str) -> Result<[u8; N]> {
    let value = field
        .strip_prefix(key)
        .and_then(|s| s.strip_prefix('='))
        .ok_or("missing provider hexadecimal field")?;
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("provider digest/payload must be exact canonical lowercase hexadecimal".into());
    }
    let mut out = [0; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
fn fields<'a>(line: &'a str, prefix: &str, count: usize, build: &str) -> Result<Vec<&'a str>> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != count
        || f[0] != prefix
        || f[1] != "protocol=1"
        || hex::<32>(f[2], "build")? != hex::<32>(&format!("build={build}"), "build")?
    {
        return Err("malformed/wrong-build provider diagnostic".into());
    }
    Ok(f)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Actor {
    Root,
    Consumer,
    Provider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Start,
    Stop,
    Reap,
    Exit,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Lifecycle {
    pub actor: Actor,
    pub kind: Kind,
    pub process: u64,
    pub thread: u64,
    pub exit_code: Option<u64>,
    pub image: [u8; 32],
}
pub(crate) fn lifecycle_line(line: &str, build: &str) -> Result<Lifecycle> {
    let f = fields(line, "EVROSION_M5_PROVIDER_LIFECYCLE", 9, build)?;
    let actor = match f[3] {
        "actor=root" => Actor::Root,
        "actor=consumer" => Actor::Consumer,
        "actor=provider" => Actor::Provider,
        _ => return Err("unknown provider actor".into()),
    };
    let kind = match f[4] {
        "event=start" => Kind::Start,
        "event=stop" => Kind::Stop,
        "event=reap" => Kind::Reap,
        "event=exit" => Kind::Exit,
        _ => return Err("unknown provider lifecycle event".into()),
    };
    let process = number(f[5], "process")?;
    let thread = number(f[6], "thread")?;
    let exit_code = if f[7] == "exit_code=none" {
        None
    } else {
        Some(number(f[7], "exit_code")?)
    };
    if process == 0
        || thread == 0
        || process == u64::MAX
        || thread == u64::MAX
        || (kind == Kind::Exit) != exit_code.is_some()
    {
        return Err("provider lifecycle has invalid identity/exit facts".into());
    }
    Ok(Lifecycle {
        actor,
        kind,
        process,
        thread,
        exit_code,
        image: hex(f[8], "image_sha256")?,
    })
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Binding {
    pub owner_process: u64,
    pub owner_thread: u64,
    pub endpoint: u64,
    pub process: u64,
    pub thread: u64,
    pub image: [u8; 32],
}
pub(crate) fn binding_line(line: &str, build: &str) -> Result<Binding> {
    let f = fields(line, "EVROSION_M5_PROVIDER_BIND", 9, build)?;
    Ok(Binding {
        owner_process: number(f[3], "owner_process")?,
        owner_thread: number(f[4], "owner_thread")?,
        endpoint: number(f[5], "endpoint")?,
        process: number(f[6], "process")?,
        thread: number(f[7], "thread")?,
        image: hex(f[8], "image_sha256")?,
    })
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Call {
    pub nonce: u64,
    pub endpoint: u64,
    pub send_handle: u64,
    pub caller_process: u64,
    pub caller_thread: u64,
    pub caller_image: [u8; 32],
    pub callee_process: u64,
    pub callee_thread: u64,
    pub callee_image: [u8; 32],
    pub request: [u8; 8],
    pub reply: [u8; 8],
}
pub(crate) fn call_line(line: &str, build: &str) -> Result<Call> {
    let f = fields(line, "EVROSION_M5_PROVIDER_CALL", 14, build)?;
    Ok(Call {
        nonce: number(f[3], "nonce")?,
        endpoint: number(f[4], "endpoint")?,
        send_handle: number(f[5], "send_handle")?,
        caller_process: number(f[6], "caller_process")?,
        caller_thread: number(f[7], "caller_thread")?,
        caller_image: hex(f[8], "caller_image_sha256")?,
        callee_process: number(f[9], "callee_process")?,
        callee_thread: number(f[10], "callee_thread")?,
        callee_image: hex(f[11], "callee_image_sha256")?,
        request: hex(f[12], "request")?,
        reply: hex(f[13], "reply")?,
    })
}
#[derive(Clone, Debug)]
struct Live {
    actor: Actor,
    process: u64,
    thread: u64,
    image: [u8; 32],
    stopped: bool,
    exit: Option<u64>,
}
impl Live {
    fn matches(&self, process: u64, thread: u64, image: [u8; 32]) -> bool {
        (self.process, self.thread, self.image) == (process, thread, image)
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct Record {
    pub root_process: u64,
    pub consumer_process: u64,
    pub consumer_thread: u64,
    pub consumer_send_handle: u64,
    pub endpoint: u64,
    pub calls: Vec<Call>,
    pub bindings: Vec<Binding>,
    pub lifecycle: Vec<Lifecycle>,
    /// Derived by this host validator from the actual opaque receipts.
    pub phase_calls: [u64; 2],
    pub returned: u64,
    pub overflow_refusals: u64,
    pub malformed_refusals: u64,
}
pub(crate) fn summary_line(line: &str, build: &str) -> Result<()> {
    let f = fields(line, "EVROSION_M5_PROVIDER", 20, build)?;
    if f[3..]
        != [
            "status=PASS",
            "actors=4",
            "starts=4",
            "stops=2",
            "reaps=4",
            "exits=2",
            "calls=10",
            "replies=10",
            "bindings=2",
            "root_exit=0",
            "consumer_exit=0",
            "outer_ready=1",
            "switch_complete=1",
            "frames=true",
            "metadata=true",
            "mappings=true",
            "authority=true",
        ]
    {
        return Err("provider completion mechanism/accounting facts differ".into());
    }
    Ok(())
}
/// Kernel collects opaque protected call/binding/lifecycle receipts only. All
/// expected algorithm/phase comparison is host-side and source-profile bound.
/// Validate an ordered transcript using its observed hashes. This is ONLY the
/// generic boot parser's syntax/history check; the selected workflow must still
/// call `record` with independently retained actual source-image hashes.
pub(crate) fn check_unbound(serial: &[u8], build: &str) -> Result<()> {
    if serial.len() > 1024 * 1024 {
        return Err("provider serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "provider serial notUTF8")?;
    let mut starts = Vec::new();
    for line in text
        .lines()
        .filter(|s| s.starts_with("EVROSION_M5_PROVIDER_LIFECYCLE"))
    {
        let event = lifecycle_line(line, build)?;
        if event.kind == Kind::Start {
            if starts.len() == 4 {
                return Err("too many provider starts".into());
            }
            starts.push(event.image);
        }
    }
    let [root, a, consumer, b] = starts.as_slice() else {
        return Err("incomplete provider start history".into());
    };
    record(
        serial,
        build,
        Images {
            root: *root,
            a: *a,
            consumer: *consumer,
            b: *b,
        },
    )
    .map(|_| ())
}

pub(crate) fn record(serial: &[u8], build: &str, images: Images) -> Result<Record> {
    if serial.len() > 1024 * 1024 {
        return Err("provider serial exceeds1MiB".into());
    }
    if [images.root, images.consumer, images.a, images.b].contains(&[0; 32]) || images.a == images.b
    {
        return Err("provider actual cohort hashes missing/not distinct".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "provider serial notUTF8")?;
    let mut live = Vec::<Live>::new();
    let mut process_ids = BTreeSet::new();
    let mut thread_ids = BTreeSet::new();
    let mut calls = Vec::new();
    let mut bindings = Vec::<Binding>::new();
    let mut lifecycle = Vec::new();
    let mut root_identity = None;
    let mut consumer_identity = None;
    let mut send_handle = None;
    let mut nonces = BTreeSet::new();
    let mut done = false;
    let mut starts = 0;
    let mut stops = 0;
    let mut reaps = 0;
    let mut exits = 0;
    let mut endpoint = None;
    for line in text
        .split_inclusive('\n')
        .filter(|l| l.ends_with('\n'))
        .map(|l| l.trim_end_matches(['\r', '\n']))
    {
        if !line.starts_with("EVROSION_M5_PROVIDER") {
            if line.starts_with("EVROSION_M3_")
                || line.starts_with("EVROSION_M4_")
                || line.starts_with("EVROSION_NATIVE_")
                || line.starts_with("EVROSION_M5_NATIVE")
            {
                return Err("provider fixture mixed another experiment".into());
            }
            continue;
        }
        if done {
            return Err("provider output follows completion".into());
        }
        if line.starts_with("EVROSION_M5_PROVIDER_LIFECYCLE ") {
            let event = lifecycle_line(line, build)?;
            if lifecycle.len() >= 16 {
                return Err("provider lifecycle budget exceeded".into());
            }
            match event.kind {
                Kind::Start => {
                    if !process_ids.insert(event.process) || !thread_ids.insert(event.thread) {
                        return Err("provider process/thread identity reused".into());
                    }
                    let expected = match (starts, event.actor) {
                        (0, Actor::Root) => images.root,
                        (1, Actor::Provider) => images.a,
                        (2, Actor::Consumer) => images.consumer,
                        (3, Actor::Provider) if calls.len() == 5 => images.b,
                        _ => return Err("provider start order/restart count differs".into()),
                    };
                    if event.image != expected {
                        return Err("provider started wrong actual cohort image".into());
                    }
                    if event.actor == Actor::Root {
                        root_identity = Some((event.process, event.thread));
                    }
                    if event.actor == Actor::Consumer {
                        consumer_identity = Some((event.process, event.thread));
                    }
                    if event.actor == Actor::Provider
                        && !bindings.last().is_some_and(|b| {
                            (b.process, b.thread, b.image)
                                == (event.process, event.thread, event.image)
                        })
                    {
                        return Err(
                            "provider start has no actual preceding receiver binding".into()
                        );
                    }
                    live.push(Live {
                        actor: event.actor,
                        process: event.process,
                        thread: event.thread,
                        image: event.image,
                        stopped: false,
                        exit: None,
                    });
                    starts += 1;
                }
                Kind::Stop => {
                    let actor = live
                        .iter_mut()
                        .find(|a| a.matches(event.process, event.thread, event.image))
                        .ok_or("provider stop has no current live owner")?;
                    if actor.actor != Actor::Provider
                        || event.actor != Actor::Provider
                        || actor.stopped
                        || actor.exit.is_some()
                        || !((actor.image == images.a && calls.len() == 5)
                            || (actor.image == images.b && calls.len() == 10))
                    {
                        return Err(
                            "provider stop before exact completed phase or duplicate".into()
                        );
                    }
                    actor.stopped = true;
                    stops += 1;
                }
                Kind::Exit => {
                    if event.actor == Actor::Root && live.iter().any(|a| a.actor != Actor::Root) {
                        return Err("provider Root exited before ordinary child retirement".into());
                    }
                    let actor = live
                        .iter_mut()
                        .find(|a| a.matches(event.process, event.thread, event.image))
                        .ok_or("provider exit has no retained owner")?;
                    if actor.actor != event.actor
                        || event.exit_code != Some(0)
                        || actor.exit.is_some()
                        || actor.stopped
                        || calls.len() != 10
                        || event.actor == Actor::Provider
                    {
                        return Err("provider unexpected/nonzero/duplicate actualExit".into());
                    }
                    actor.exit = Some(0);
                    exits += 1;
                }
                Kind::Reap => {
                    let index = live
                        .iter()
                        .position(|a| a.matches(event.process, event.thread, event.image))
                        .ok_or("provider reap has no retained owner")?;
                    let actor = &live[index];
                    if actor.actor != event.actor || !actor.stopped && actor.exit != Some(0) {
                        return Err(
                            "provider physical reap without actual stopped/exited owner".into()
                        );
                    }
                    live.remove(index);
                    reaps += 1;
                }
            }
            lifecycle.push(event);
        } else if line.starts_with("EVROSION_M5_PROVIDER_BIND ") {
            let binding = binding_line(line, build)?;
            if bindings.len() >= 2
                || Some((binding.owner_process, binding.owner_thread)) != root_identity
                || binding.process == 0
                || binding.thread == 0
            {
                return Err("provider binding has wrong actual Root or budget".into());
            }
            let expected = if bindings.is_empty() {
                images.a
            } else {
                images.b
            };
            if binding.image != expected
                || bindings.len() == 1
                    && (calls.len() != 5 || live.iter().any(|a| a.actor == Actor::Provider))
            {
                return Err(
                    "provider binding precedes old physical retirement or wrong image".into(),
                );
            }
            if endpoint.is_some_and(|old| old != binding.endpoint) {
                return Err("provider replaced the endpoint object".into());
            }
            endpoint = Some(binding.endpoint);
            bindings.push(binding);
        } else if line.starts_with("EVROSION_M5_PROVIDER_CALL ") {
            let call = call_line(line, build)?;
            if calls.len() >= 10
                || call.nonce == 0
                || call.nonce == u64::MAX
                || !nonces.insert(call.nonce)
                || call.send_handle == 0
                || call.send_handle == u64::MAX
                || Some(call.endpoint) != endpoint
                || Some((call.caller_process, call.caller_thread)) != consumer_identity
                || call.caller_image != images.consumer
            {
                return Err(
                    "provider call lost nonce/consumer/endpoint/installed handle identity".into(),
                );
            }
            if send_handle.is_some_and(|old| old != call.send_handle) {
                return Err("provider consumer SEND grant changed between phases".into());
            }
            send_handle = Some(call.send_handle);
            if !live.iter().any(|a| {
                a.actor == Actor::Consumer
                    && !a.stopped
                    && a.exit.is_none()
                    && a.matches(call.caller_process, call.caller_thread, call.caller_image)
            }) {
                return Err("provider caller not the same actual live consumer".into());
            }
            let expected = if calls.len() < 5 { images.a } else { images.b };
            if call.callee_image != expected
                || !live.iter().any(|a| {
                    a.actor == Actor::Provider
                        && !a.stopped
                        && a.exit.is_none()
                        && a.matches(call.callee_process, call.callee_thread, call.callee_image)
                })
            {
                return Err("provider reply came from wrong/unadmitted/stopped receiver".into());
            }
            let (request, reply) = match calls.len() % 5 {
                0 => (
                    wire::Request { value: 0 }.encode(),
                    wire::Response::Returned(1).encode(),
                ),
                1 => (
                    wire::Request { value: 137 }.encode(),
                    wire::Response::Returned(275).encode(),
                ),
                2 => (
                    wire::Request {
                        value: wire::MAX_INPUT,
                    }
                    .encode(),
                    wire::Response::Returned(u32::MAX).encode(),
                ),
                3 => (
                    wire::Request { value: u32::MAX }.encode(),
                    wire::Response::Refused(wire::Refusal::Overflow).encode(),
                ),
                _ => (
                    [0; 8],
                    wire::Response::Refused(wire::Refusal::Malformed).encode(),
                ),
            };
            if call.request != request || call.reply != reply {
                return Err("provider actual request/reply differs from unchanged contract".into());
            }
            calls.push(call);
        } else if line.starts_with("EVROSION_M5_PROVIDER ") {
            summary_line(line, build)?;
            if (starts, stops, reaps, exits) != (4, 2, 4, 2)
                || calls.len() != 10
                || bindings.len() != 2
                || !live.is_empty()
            {
                return Err(
                    "provider completion differs from retained actual mechanism history".into(),
                );
            }
            done = true;
        } else {
            return Err("unknown provider diagnostic".into());
        }
    }
    if !done {
        return Err("provider completion missing/truncated".into());
    }
    let (root_process, _) = root_identity.ok_or("provider Root absent")?;
    let (consumer_process, consumer_thread) =
        consumer_identity.ok_or("provider consumer absent")?;
    Ok(Record {
        root_process,
        consumer_process,
        consumer_thread,
        consumer_send_handle: send_handle.ok_or("provider SEND absent")?,
        endpoint: endpoint.ok_or("provider endpoint absent")?,
        calls,
        bindings,
        lifecycle,
        phase_calls: [5, 5],
        returned: 6,
        overflow_refusals: 2,
        malformed_refusals: 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hash(value: [u8; 32]) -> String {
        value.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn payload(value: [u8; 8]) -> String {
        value.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn fixture() -> (String, String, Images) {
        let build = "a".repeat(64);
        let images = Images {
            root: [1; 32],
            consumer: [2; 32],
            a: [3; 32],
            b: [4; 32],
        };
        let mut lines = Vec::new();
        let life = |actor: &str,
                    event: &str,
                    process: u64,
                    thread: u64,
                    image: [u8; 32],
                    exit: &str| {
            format!(
                "EVROSION_M5_PROVIDER_LIFECYCLE protocol=1 build={build} actor={actor} event={event} process={process} thread={thread} exit_code={exit} image_sha256={}",
                hash(image)
            )
        };
        let bind = |process: u64, thread: u64, image: [u8; 32]| {
            format!(
                "EVROSION_M5_PROVIDER_BIND protocol=1 build={build} owner_process=1 owner_thread=1 endpoint=8 process={process} thread={thread} image_sha256={}",
                hash(image)
            )
        };
        lines.push(life("root", "start", 1, 1, images.root, "none"));
        lines.push(bind(2, 2, images.a));
        lines.push(life("provider", "start", 2, 2, images.a, "none"));
        lines.push(life("consumer", "start", 3, 3, images.consumer, "none"));
        for phase in 0..2 {
            let (callee_process, callee_thread, image) = if phase == 0 {
                (2, 2, images.a)
            } else {
                (258, 258, images.b)
            };
            for index in 0..5 {
                let (request, reply) = match index {
                    0 => (
                        wire::Request { value: 0 }.encode(),
                        wire::Response::Returned(1).encode(),
                    ),
                    1 => (
                        wire::Request { value: 137 }.encode(),
                        wire::Response::Returned(275).encode(),
                    ),
                    2 => (
                        wire::Request {
                            value: wire::MAX_INPUT,
                        }
                        .encode(),
                        wire::Response::Returned(u32::MAX).encode(),
                    ),
                    3 => (
                        wire::Request { value: u32::MAX }.encode(),
                        wire::Response::Refused(wire::Refusal::Overflow).encode(),
                    ),
                    _ => (
                        [0; 8],
                        wire::Response::Refused(wire::Refusal::Malformed).encode(),
                    ),
                };
                lines.push(format!("EVROSION_M5_PROVIDER_CALL protocol=1 build={build} nonce={} endpoint=8 send_handle=257 caller_process=3 caller_thread=3 caller_image_sha256={} callee_process={callee_process} callee_thread={callee_thread} callee_image_sha256={} request={} reply={}",phase*5+index+1,hash(images.consumer),hash(image),payload(request),payload(reply)));
            }
            if phase == 0 {
                lines.push(life("provider", "stop", 2, 2, images.a, "none"));
                lines.push(life("provider", "reap", 2, 2, images.a, "none"));
                lines.push(bind(258, 258, images.b));
                lines.push(life("provider", "start", 258, 258, images.b, "none"));
            }
        }
        lines.push(life("consumer", "exit", 3, 3, images.consumer, "0"));
        lines.push(life("consumer", "reap", 3, 3, images.consumer, "none"));
        lines.push(life("provider", "stop", 258, 258, images.b, "none"));
        lines.push(life("provider", "reap", 258, 258, images.b, "none"));
        lines.push(life("root", "exit", 1, 1, images.root, "0"));
        lines.push(life("root", "reap", 1, 1, images.root, "none"));
        lines.push(format!("EVROSION_M5_PROVIDER protocol=1 build={build} status=PASS actors=4 starts=4 stops=2 reaps=4 exits=2 calls=10 replies=10 bindings=2 root_exit=0 consumer_exit=0 outer_ready=1 switch_complete=1 frames=true metadata=true mappings=true authority=true"));
        (format!("{}\r\n", lines.join("\r\n")), build, images)
    }
    #[test]
    fn complete_source_bound_receipts_require_same_consumer_handle_endpoint_and_actual_zero_exits()
    {
        let (serial, build, images) = fixture();
        let actual = record(serial.as_bytes(), &build, images).unwrap();
        assert_eq!(actual.calls.len(), 10);
        assert_eq!(actual.bindings.len(), 2);
        assert_eq!(actual.consumer_process, 3);
        assert_eq!(actual.consumer_send_handle, 257);
        assert_eq!(actual.endpoint, 8);
    }
    #[test]
    fn replacement_cannot_hide_consumer_restart_handle_replacement_forged_answers_or_nonzero_exit()
    {
        let (serial, build, images) = fixture();
        for bad in [
            serial.replace("send_handle=257", "send_handle=0257"),
            serial.replace("nonce=6 ", "nonce=5 "),
            serial.replacen("send_handle=257", "send_handle=258", 1),
            serial.replace("caller_process=3", "caller_process=259"),
            serial.replacen("endpoint=8", "endpoint=9", 1),
            serial.replace("exit_code=0", "exit_code=1"),
            serial.replacen("reply=5056010201000000", "reply=5056010202000000", 1),
            serial.replace("image_sha256=040404", "image_sha256=030303"),
            serial.replacen("calls=10", "calls=9", 1),
            serial.trim_end_matches(['\r', '\n']).to_owned(),
        ] {
            assert!(record(bad.as_bytes(), &build, images).is_err());
        }
        assert!(record(serial.as_bytes(), &"b".repeat(64), images).is_err());
    }
    #[test]
    fn out_of_order_stop_reap_binding_completion_or_duplicate_receipts_never_pass() {
        let (serial, build, images) = fixture();
        let lines: Vec<_> = serial.lines().collect();
        for (a, b) in [(9, 10), (10, 11), (9, 11)] {
            let mut changed = lines.clone();
            changed.swap(a, b);
            assert!(
                record(
                    format!("{}\n", changed.join("\n")).as_bytes(),
                    &build,
                    images
                )
                .is_err()
            );
        }
        let call = lines
            .iter()
            .find(|line| line.starts_with("EVROSION_M5_PROVIDER_CALL"))
            .unwrap();
        assert!(record(format!("{call}\n{serial}").as_bytes(), &build, images).is_err());
        let summary = lines.last().unwrap();
        assert!(record(format!("{serial}{summary}\n").as_bytes(), &build, images).is_err());
        assert!(
            record(
                serial
                    .replace("EVROSION_M5_PROVIDER_BIND", "EVROSION_M5_PROVIDER_UNKNOWN")
                    .as_bytes(),
                &build,
                images
            )
            .is_err()
        );
    }
    /// Synthetic provider receipts between a retained actual common prelude and
    /// postlude. This is parser integration evidence, never a provider VM PASS.
    fn full_boot(body: &str, build: &str) -> String {
        let baseline = include_str!("../../../tests/fixtures/native-scheduling-profile-parser.log");
        let source_build = baseline
            .lines()
            .find_map(|line| line.strip_prefix("EVROSION_BOOT protocol=1 build="))
            .unwrap();
        let discipline = baseline.find("EVROSION_M2_IPC_DISCIPLINE ").unwrap();
        let prefix_end = discipline + baseline[discipline..].find('\n').unwrap() + 1;
        let postfix = baseline.find("EVROSION_M1_RUNTIME ").unwrap();
        format!(
            "{}{}{}",
            baseline[..prefix_end].replace(source_build, build),
            body,
            baseline[postfix..].replace(source_build, build)
        )
    }
    fn generic_boot(serial: &str, build: &str) -> Result<()> {
        crate::boot_protocol::check(
            serial.as_bytes(),
            build,
            Some(ev_test_protocol::QEMU_PASS_STATUS),
        )
    }
    #[test]
    fn complete_provider_boot_accepts_common_protocol_and_requires_order_and_actual_exit_status() {
        let (body, build, images) = fixture();
        let serial = full_boot(&body, &build);
        generic_boot(&serial, &build).unwrap();
        let record = record(serial.as_bytes(), &build, images).unwrap();
        assert_eq!(record.phase_calls, [5, 5]);
        assert_eq!(
            (
                record.returned,
                record.overflow_refusals,
                record.malformed_refusals
            ),
            (6, 2, 2)
        );
        assert!(crate::boot_protocol::check(serial.as_bytes(), &build, None).is_err());
        assert!(
            crate::boot_protocol::check(
                serial.as_bytes(),
                &build,
                Some(ev_test_protocol::QEMU_FAIL_STATUS)
            )
            .is_err()
        );
        let early = serial.replacen(&body, "", 1).replacen(
            "EVROSION_M2_IPC_DISCIPLINE ",
            &format!("{body}EVROSION_M2_IPC_DISCIPLINE "),
            1,
        );
        assert!(generic_boot(&early, &build).is_err());
        let truncated = serial.split("EVROSION_M0_RESULT").next().unwrap();
        assert!(generic_boot(truncated, &build).is_err());
    }
    #[test]
    fn full_provider_boot_rejects_missing_replayed_and_wrong_build_records_in_both_layers() {
        let (body, build, images) = fixture();
        for prefix in [
            "EVROSION_M5_PROVIDER_BIND ",
            "EVROSION_M5_PROVIDER_CALL ",
            "EVROSION_M5_PROVIDER ",
        ] {
            let line = body.lines().find(|line| line.starts_with(prefix)).unwrap();
            for changed in [
                body.replacen(&format!("{line}\r\n"), "", 1),
                body.replacen(line, &format!("{line}\r\n{line}"), 1),
            ] {
                assert_ne!(changed, body);
                let serial = full_boot(&changed, &build);
                assert!(
                    generic_boot(&serial, &build).is_err(),
                    "generic accepted {prefix}"
                );
                assert!(
                    record(serial.as_bytes(), &build, images).is_err(),
                    "selected accepted {prefix}"
                );
            }
        }
        let changed = body.replacen(
            &format!("build={build}"),
            &format!("build={}", "b".repeat(64)),
            1,
        );
        let serial = full_boot(&changed, &build);
        assert!(generic_boot(&serial, &build).is_err());
        assert!(record(serial.as_bytes(), &build, images).is_err());
        let serial = full_boot(&body, &build);
        assert!(generic_boot(&serial, &"b".repeat(64)).is_err());
        assert!(record(serial.as_bytes(), &"b".repeat(64), images).is_err());
    }
    #[test]
    fn full_provider_boot_rejects_mixed_native_receipts_and_individual_pid_or_tid_reuse() {
        let (body, build, images) = fixture();
        let baseline = include_str!("../../../tests/fixtures/native-scheduling-profile-parser.log");
        let native = baseline
            .lines()
            .find(|line| line.starts_with("EVROSION_NATIVE_STATE "))
            .unwrap();
        let source_build = baseline
            .lines()
            .find_map(|line| line.strip_prefix("EVROSION_BOOT protocol=1 build="))
            .unwrap();
        let mixed = format!("{body}{}\r\n", native.replace(source_build, &build));
        let mut malformed = vec![mixed];
        malformed.push(
            body.replace("process=258 thread=258", "process=2 thread=258")
                .replace("callee_process=258", "callee_process=2"),
        );
        malformed.push(
            body.replace("process=258 thread=258", "process=258 thread=2")
                .replace("callee_thread=258", "callee_thread=2"),
        );
        for changed in malformed {
            assert_ne!(changed, body);
            let serial = full_boot(&changed, &build);
            assert!(
                generic_boot(&serial, &build).is_err(),
                "generic accepted malformed history"
            );
            assert!(
                record(serial.as_bytes(), &build, images).is_err(),
                "selected accepted malformed history"
            );
        }
    }
    #[test]
    fn generic_history_acceptance_cannot_replace_independent_actual_source_binding() {
        let (body, build, images) = fixture();
        let serial = full_boot(&body, &build);
        generic_boot(&serial, &build).unwrap();
        check_unbound(serial.as_bytes(), &build).unwrap();
        for selected in [
            Images {
                root: [9; 32],
                ..images
            },
            Images {
                consumer: [9; 32],
                ..images
            },
            Images {
                a: [9; 32],
                ..images
            },
            Images {
                b: [9; 32],
                ..images
            },
        ] {
            assert!(record(serial.as_bytes(), &build, selected).is_err());
        }
        record(serial.as_bytes(), &build, images).unwrap();
    }
}
