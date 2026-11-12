//! Actual batched SDK RPC observations. Source sample is not Kernel CPU time.
use crate::{boot_protocol::canonical_number, build::Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Id {
    process: u64,
    thread: u64,
    image: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    root: Id,
    client: Id,
    server: Id,
    endpoint: u64,
    send_handle: u64,
}
#[derive(Clone, Debug)]
struct Batch {
    tick: u64,
    calls: u64,
    last_nonce: u64,
    first_nonce: u64,
    route: Route,
}
#[derive(Clone, Copy)]
pub(crate) struct Images {
    pub root: [u8; 32],
    pub client: [u8; 32],
    pub server: [u8; 32],
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(v: &str, key: &str) -> Result<String> {
    let v = v
        .strip_prefix(key)
        .and_then(|s| s.strip_prefix('='))
        .ok_or("IPC digest missing")?;
    if v.len() != 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("IPC digest not canonical64hex".into());
    }
    Ok(v.into())
}
fn field<'a>(v: &'a str, key: &str) -> Result<&'a str> {
    v.strip_prefix(key)
        .and_then(|s| s.strip_prefix('='))
        .ok_or("IPC field missing".into())
}
fn id(f: &[&str], name: &str) -> Result<Id> {
    let process = canonical_number(f[0], &format!("{name}_process"))?;
    let thread = canonical_number(f[1], &format!("{name}_thread"))?;
    if [process, thread].iter().any(|n| *n == 0 || *n == u64::MAX) {
        return Err("IPC invalid actual process/thread".into());
    }
    Ok(Id {
        process,
        thread,
        image: digest(f[2], &format!("{name}_image_sha256"))?,
    })
}
fn batch(f: &[&str], expected: u64) -> Result<Batch> {
    if f.len() != 22 {
        return Err("IPC batch fieldcount differs".into());
    }
    let tick = canonical_number(f[4], "tick")?;
    let calls = canonical_number(f[5], "calls")?;
    let replies = canonical_number(f[6], "replies")?;
    let rejected = canonical_number(f[7], "rejected")?;
    let completed = canonical_number(f[8], "completed")?;
    let first_nonce = canonical_number(f[9], "first_nonce")?;
    let last_nonce = canonical_number(f[10], "last_nonce")?;
    let endpoint = canonical_number(f[11], "endpoint")?;
    let send_handle = canonical_number(f[12], "send_handle")?;
    if calls != expected
        || replies != calls
        || completed != calls
        || rejected != 0
        || first_nonce == 0
        || last_nonce
            .checked_sub(first_nonce)
            .and_then(|n| n.checked_add(1))
            != Some(calls)
        || endpoint == 0
        || send_handle == 0
    {
        return Err("IPC actual counters/nonces differ from checked fixed batch".into());
    }
    Ok(Batch {
        tick,
        calls,
        first_nonce,
        last_nonce,
        route: Route {
            root: id(&f[13..16], "root")?,
            client: id(&f[16..19], "client")?,
            server: id(&f[19..22], "server")?,
            endpoint,
            send_handle,
        },
    })
}
pub(crate) fn line(line: &str, build: &str) -> Result<()> {
    let f: Vec<_> = line.split(' ').collect();
    if f.len() < 3 || line.len() > 2048 || f[1] != "protocol=1" || digest(f[2], "build")? != build {
        return Err("IPC syntax/wrong-build".into());
    }
    match f[0] {
        "EVROSION_M5_IPC_LIFECYCLE" if f.len() == 9 => {
            field(f[3], "actor")?;
            field(f[4], "event")?;
            id(&f[5..8], "actor")?;
            field(f[8], "exit_code")?;
        }
        "EVROSION_M5_IPC_READY" | "EVROSION_M5_IPC_FINISH" if f.len() == 6 => {
            id(&f[3..6], "root")?;
        }
        "EVROSION_M5_IPC_BINDING" if f.len() == 10 => {
            canonical_number(f[3], "endpoint")?;
            id(&f[4..7], "root")?;
            id(&f[7..10], "server")?;
        }
        "EVROSION_M5_IPC_BATCH" if f.len() == 22 => {
            let p = field(f[3], "phase")?;
            if !matches!(p, "before" | "after") {
                return Err("IPC unknown phase".into());
            }
            batch(&f, if p == "before" { 64 } else { 4160 })?;
        }
        "EVROSION_M5_IPC_SAMPLE" if f.len() == 10 => {
            for (v, k) in f[3..7]
                .iter()
                .zip(["warmups", "rounds", "first_tick", "last_tick"])
            {
                canonical_number(v, k)?;
            }
            id(&f[7..10], "root")?;
        }
        "EVROSION_M5_IPC" if f.len() == 22 => {
            if f[3] != "status=PASS" {
                return Err("IPC incomplete footer".into());
            }
        }
        _ => return Err("IPC unknown/malformed closed observation".into()),
    }
    Ok(())
}
pub(crate) fn check_unbound(serial: &[u8], build: &str) -> Result<()> {
    let text = std::str::from_utf8(serial).map_err(|_| "IPC serial notUTF8")?;
    let mut images = BTreeMap::new();
    for l in text
        .lines()
        .filter(|l| l.starts_with("EVROSION_M5_IPC_LIFECYCLE "))
    {
        let f: Vec<_> = l.split(' ').collect();
        if f.len() != 9 {
            return Err("IPC lifecycle malformed".into());
        }
        if f[4] == "event=start" {
            let actor = field(f[3], "actor")?;
            let hash = digest(f[7], "actor_image_sha256")?;
            let mut bytes = [0; 32];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
            }
            if images.insert(actor, bytes).is_some() {
                return Err("IPC duplicate source image".into());
            }
        }
    }
    record(
        serial,
        build,
        Images {
            root: *images.get("root").ok_or("IPC Root missing")?,
            client: *images.get("client").ok_or("IPC client missing")?,
            server: *images.get("server").ok_or("IPC server missing")?,
        },
    )?;
    Ok(())
}
/// Independent joins against exact retained source-built component hashes.
pub(crate) fn record(serial: &[u8], build: &str, images: Images) -> Result<Value> {
    if serial.len() > 1024 * 1024 || !serial.ends_with(b"\n") {
        return Err("IPC serial truncated/over1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "IPC serial notUTF8")?;
    let mut live: BTreeMap<String, (Id, u8)> = BTreeMap::new();
    let mut ready = false;
    let mut binding = None;
    let mut before = None;
    let mut after = None;
    let mut sample = None;
    let mut finished = false;
    let mut footer = false;
    for line in text.lines() {
        if line.starts_with("EVROSION_M5_PROVIDER") {
            return Err("IPC benchmark mixed provider replacement evidence".into());
        }
        if !line.starts_with("EVROSION_M5_IPC") {
            continue;
        }
        let f: Vec<_> = line.split(' ').collect();
        if line.len() > 2048
            || f.len() < 3
            || f[1] != "protocol=1"
            || digest(f[2], "build")? != build
            || footer
        {
            return Err("IPC malformed/wrong-build/late observation".into());
        }
        match f[0] {
            "EVROSION_M5_IPC_LIFECYCLE" => {
                if f.len() != 9 {
                    return Err("IPC lifecycle malformed".into());
                }
                let actor = field(f[3], "actor")?;
                let expected = match actor {
                    "root" => hex(&images.root),
                    "client" => hex(&images.client),
                    "server" => hex(&images.server),
                    _ => return Err("IPC unknown actor".into()),
                };
                let identity = id(&f[5..8], "actor")?;
                if identity.image != expected {
                    return Err("IPC lifecycle image not actual retained component".into());
                }
                let event = field(f[4], "event")?;
                match event {
                    "start" => {
                        if live.contains_key(actor)
                            || live.values().any(|(i, _)| {
                                i.process == identity.process || i.thread == identity.thread
                            })
                            || f[8] != "exit_code=none"
                        {
                            return Err("IPC duplicate/reused actual actor identity".into());
                        }
                        live.insert(actor.into(), (identity, 1));
                    }
                    "exit" => {
                        let entry = live.get_mut(actor).ok_or("IPC unknown exiting actor")?;
                        if actor == "server"
                            || entry.0 != identity
                            || entry.1 != 1
                            || f[8] != "exit_code=0"
                            || actor == "root" && !finished
                        {
                            return Err("IPC actual nonzero/late/unknown Exit".into());
                        }
                        entry.1 = 2;
                    }
                    "stop" => {
                        let entry = live.get_mut(actor).ok_or("IPC unknown stopped actor")?;
                        if actor != "server"
                            || entry.0 != identity
                            || entry.1 != 1
                            || after.is_none()
                            || f[8] != "exit_code=none"
                        {
                            return Err("IPC server stop before batch quiescence".into());
                        }
                        entry.1 = 2;
                    }
                    "reap" => {
                        let entry = live.get_mut(actor).ok_or("IPC unknown reaped actor")?;
                        if entry.0 != identity || entry.1 != 2 || f[8] != "exit_code=none" {
                            return Err("IPC reap before actual Exit/Stop".into());
                        }
                        entry.1 = 3;
                    }
                    _ => return Err("IPC unknown lifecycle event".into()),
                }
            }
            "EVROSION_M5_IPC_READY" => {
                if f.len() != 6
                    || ready
                    || id(&f[3..], "root")? != live.get("root").ok_or("IPC Root not started")?.0
                {
                    return Err("IPC wrong/repeated actual Root ready".into());
                }
                ready = true;
            }
            "EVROSION_M5_IPC_BINDING" => {
                if f.len() != 10 || binding.is_some() || before.is_some() {
                    return Err("IPC repeated/late receiver binding".into());
                }
                let endpoint = canonical_number(f[3], "endpoint")?;
                let root = id(&f[4..7], "root")?;
                let server = id(&f[7..10], "server")?;
                if endpoint == 0
                    || root != live.get("root").ok_or("IPC missing Root")?.0
                    || server.image != hex(&images.server)
                {
                    return Err("IPC binding source differs".into());
                }
                binding = Some((endpoint, root, server));
            }
            "EVROSION_M5_IPC_BATCH" => {
                if f.len() != 22 {
                    return Err("IPC batch fields missing".into());
                }
                let phase = field(f[3], "phase")?;
                let b = batch(&f, if phase == "before" { 64 } else { 4160 })?;
                if !ready
                    || live.get("root").map(|x| &x.0) != Some(&b.route.root)
                    || live.get("client").map(|x| &x.0) != Some(&b.route.client)
                    || live.get("server").map(|x| &x.0) != Some(&b.route.server)
                    || binding.as_ref()
                        != Some(&(
                            b.route.endpoint,
                            b.route.root.clone(),
                            b.route.server.clone(),
                        ))
                {
                    return Err("IPC batch route/actual owner differs from retained graph".into());
                }
                if live.get("root").is_none_or(|x| x.1 != 1)
                    || live.get("server").is_none_or(|x| x.1 != 1)
                    || phase == "before" && live.get("client").is_none_or(|x| x.1 != 1)
                {
                    return Err("IPC measurement contains a stopped/reaped participant".into());
                }
                match phase {
                    "before" if before.is_none() && after.is_none() => before = Some(b),
                    "after" if after.is_none() => {
                        let prior = before.as_ref().ok_or("IPC after without before")?;
                        if b.tick < prior.tick
                            || b.route != prior.route
                            || b.first_nonce != prior.first_nonce
                            || b.last_nonce - prior.last_nonce != 4096
                            || b.calls - prior.calls != 4096
                        {
                            return Err(
                                "IPC measured batch changed route/identity/nonce/count".into()
                            );
                        }
                        after = Some(b);
                    }
                    _ => return Err("IPC batch replay/gap/unknown phase".into()),
                }
            }
            "EVROSION_M5_IPC_SAMPLE" => {
                if f.len() != 10
                    || sample.is_some()
                    || after.is_none()
                    || canonical_number(f[3], "warmups")? != 64
                    || canonical_number(f[4], "rounds")? != 4096
                    || id(&f[7..10], "root")? != live.get("root").unwrap().0
                {
                    return Err("IPC source sample malformed/replayed/unauthenticated".into());
                }
                let first = canonical_number(f[5], "first_tick")?;
                let last = canonical_number(f[6], "last_tick")?;
                if first > last
                    || first < before.as_ref().unwrap().tick
                    || last > after.as_ref().unwrap().tick
                {
                    return Err("IPC source clock not within actual Kernel batch bracket".into());
                }
                sample = Some((first, last));
            }
            "EVROSION_M5_IPC_FINISH" => {
                if f.len() != 6
                    || finished
                    || sample.is_none()
                    || id(&f[3..6], "root")? != live.get("root").unwrap().0
                    || live.get("client").is_none_or(|x| x.1 != 3)
                    || live.get("server").is_none_or(|x| x.1 != 3)
                {
                    return Err("IPC Root finish preceded actual actor retirement".into());
                }
                finished = true;
            }
            "EVROSION_M5_IPC" => {
                let expected = [
                    "status=PASS",
                    "actors=3",
                    "starts=3",
                    "stops=1",
                    "reaps=3",
                    "exits=2",
                    "calls=4160",
                    "replies=4160",
                    "rejected=0",
                    "bindings=1",
                    "root_exit=0",
                    "client_exit=0",
                    "outer_ready=1",
                    "batch_finished=1",
                    "switch_complete=0",
                    "frames=true",
                    "metadata=true",
                    "mappings=true",
                    "authority=true",
                ];
                if f[3..] != expected
                    || !finished
                    || live.len() != 3
                    || live.values().any(|(_, s)| *s != 3)
                {
                    return Err(
                        "IPC completion lacks exact actual resource/authority cleanup".into(),
                    );
                }
                footer = true;
            }
            _ => return Err("IPC unknown benchmark observation".into()),
        }
    }
    if !footer {
        return Err("IPC actual completion missing".into());
    }
    let (first, last) = sample.unwrap();
    let delta = last - first;
    let before = before.unwrap();
    let after = after.unwrap();
    Ok(
        json!({"schema":1,"kind":"actual-checked-sdk-rpc-batch","warmups":64,"measured_rounds":4096,"actual_total_calls":4160,"route":{"root_process":before.route.root.process,"root_thread":before.route.root.thread,"root_image":before.route.root.image,"client_process":before.route.client.process,"client_thread":before.route.client.thread,"client_image":before.route.client.image,"server_process":before.route.server.process,"server_thread":before.route.server.thread,"server_image":before.route.server.image,"endpoint":before.route.endpoint,"send_handle":before.route.send_handle},"counter_before":{"calls":before.calls,"first_nonce":before.first_nonce,"last_nonce":before.last_nonce},"counter_after":{"calls":after.calls,"first_nonce":after.first_nonce,"last_nonce":after.last_nonce},"before_delivered_irq_ticks":before.tick,"after_delivered_irq_ticks":after.tick,"client_first_delivered_irq_ticks":first,"client_last_delivered_irq_ticks":last,"client_span_delivered_irq_ticks":delta,"mean_sdk_roundtrip_delivered_irq_ticks":{"numerator":delta,"denominator":4096},"below_delivered_tick_resolution":delta==0,"clock_scope":"delivered guest IRQ count; neither calibrated ns nor raw IPC trap cycles","per_call_uart":false,"outstanding_rpc_limit":1,"actual_root_and_client_exit_zero":true,"actual_server_stop_and_all_reaps":true,"full_owned_cleanup":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn build() -> String {
        "d".repeat(64)
    }
    fn component(name: &str) -> String {
        let (n, h) = match name {
            "root" => (11, 'a'),
            "client" => (12, 'b'),
            _ => (13, 'c'),
        };
        format!(
            "{name}_process={n} {name}_thread={} {name}_image_sha256={}",
            n + 90,
            h.to_string().repeat(64)
        )
    }
    fn life(actor: &str, event: &str) -> String {
        let (n, h) = match actor {
            "root" => (11, 'a'),
            "client" => (12, 'b'),
            _ => (13, 'c'),
        };
        format!(
            "EVROSION_M5_IPC_LIFECYCLE protocol=1 build={} actor={actor} event={event} actor_process={n} actor_thread={} actor_image_sha256={} exit_code={}\n",
            build(),
            n + 90,
            h.to_string().repeat(64),
            if event == "exit" { "0" } else { "none" }
        )
    }
    fn fixture() -> String {
        let mut s = life("root", "start");
        s += &format!(
            "EVROSION_M5_IPC_READY protocol=1 build={} {}\n",
            build(),
            component("root")
        );
        s += &format!(
            "EVROSION_M5_IPC_BINDING protocol=1 build={} endpoint=7 {} {}\n",
            build(),
            component("root"),
            component("server")
        );
        s += &life("server", "start");
        s += &life("client", "start");
        for (phase, tick, n) in [("before", 10, 64), ("after", 20, 4160)] {
            s += &format!(
                "EVROSION_M5_IPC_BATCH protocol=1 build={} phase={phase} tick={tick} calls={n} replies={n} rejected=0 completed={n} first_nonce=1 last_nonce={n} endpoint=7 send_handle=513 {} {} {}\n",
                build(),
                component("root"),
                component("client"),
                component("server")
            );
        }
        s += &format!(
            "EVROSION_M5_IPC_SAMPLE protocol=1 build={} warmups=64 rounds=4096 first_tick=11 last_tick=19 {}\n",
            build(),
            component("root")
        );
        s += &life("client", "exit");
        s += &life("client", "reap");
        s += &life("server", "stop");
        s += &life("server", "reap");
        s += &format!(
            "EVROSION_M5_IPC_FINISH protocol=1 build={} {}\n",
            build(),
            component("root")
        );
        s += &life("root", "exit");
        s += &life("root", "reap");
        s += &format!(
            "EVROSION_M5_IPC protocol=1 build={} status=PASS actors=3 starts=3 stops=1 reaps=3 exits=2 calls=4160 replies=4160 rejected=0 bindings=1 root_exit=0 client_exit=0 outer_ready=1 batch_finished=1 switch_complete=0 frames=true metadata=true mappings=true authority=true\n",
            build()
        );
        s
    }
    fn checked(serial: &str) -> Result<Value> {
        record(
            serial.as_bytes(),
            &build(),
            Images {
                root: [0xaa; 32],
                client: [0xbb; 32],
                server: [0xcc; 32],
            },
        )
    }
    #[test]
    fn full_owned_batch_keeps_guest_units_and_exact_rational() {
        let s = fixture();
        let r = checked(&s).unwrap();
        for l in s.lines() {
            line(l, &build()).unwrap();
        }
        check_unbound(s.as_bytes(), &build()).unwrap();
        assert_eq!(r["mean_sdk_roundtrip_delivered_irq_ticks"]["numerator"], 8);
        assert_eq!(
            r["mean_sdk_roundtrip_delivered_irq_ticks"]["denominator"],
            4096
        );
        let zero = s.replace("first_tick=11 last_tick=19", "first_tick=11 last_tick=11");
        assert_eq!(
            checked(&zero).unwrap()["below_delivered_tick_resolution"],
            true
        );
    }
    #[test]
    fn altered_counts_routes_identities_or_clock_cannot_relabel_functional_calls() {
        let s = fixture();
        for bad in [
            s.replace("calls=4160", "calls=10"),
            s.replace("replies=4160", "replies=4159"),
            s.replace("rejected=0", "rejected=1"),
            s.replacen("send_handle=513", "send_handle=514", 1),
            s.replacen("client_process=12", "client_process=99", 1),
            s.replace("rounds=4096", "rounds=10"),
            s.replace("last_tick=19", "last_tick=21"),
            s.replace("client_exit=0", "client_exit=1"),
            s.replace("switch_complete=0", "switch_complete=1"),
            s.replace("frames=true", "frames=false"),
        ] {
            assert!(checked(&bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn replay_truncation_foreignbuild_mixedprofile_and_missing_retirement_refuse() {
        let s = fixture();
        let before = s.lines().find(|l| l.contains("phase=before")).unwrap();
        for bad in [
            s.replacen(before, &format!("{before}\n{before}"), 1),
            s.trim_end().into(),
            s.replace("protocol=1", "protocol=01"),
            s.replace(&build(), &"e".repeat(64)),
            s.replace(&life("server", "reap"), ""),
            s.replace(&life("client", "exit"), ""),
            format!("EVROSION_M5_PROVIDER status=PASS\n{s}"),
            s.replace("phase=before tick=10", "phase=after tick=10"),
        ] {
            assert!(checked(&bad).is_err());
        }
        assert!(checked("EVROSION_M5_IPC_BATCH protocol=1 build=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n").is_err());
    }
}
