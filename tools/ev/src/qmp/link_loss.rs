//! One owned reference-VM transport disconnect. QEMU10.2.1 reports NIC/peer
//! identity through info-network; set_link ACK changes NetClientState. NE2K
//! has no PHY-notification callback, so no guest link event is invented here.
use super::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
const NIC_NAME: &str = "ne2k_isa.0";
const NIC_LINE: &str = "ne2k_isa.0: index=0,type=nic,model=ne2k_isa,macaddr=02:45:56:52:00:01";
const PEER_LINE: &str = " \\ evnet: index=0,type=user,net=10.0.2.0,restrict=off";
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ReferenceLinkDown {
    device: &'static str,
    backend: &'static str,
    model: &'static str,
    mac: &'static str,
    command_id: u64,
    before_table_sha256: String,
    after_table_sha256: String,
    qmp_set_link_acknowledged: bool,
    guest_phy_notification_claim: bool,
}
fn table(value: &Value) -> Result<&str> {
    let text = value
        .as_str()
        .filter(|s| s.len() <= 2048 && s.ends_with('\n'))
        .ok_or("reference network table type/bound/completeness")?;
    let lines: Vec<_> = text.lines().collect();
    if lines != [NIC_LINE, PEER_LINE] {
        return Err("reference network table is not the exact owned NE2K/MAC/evnet pair".into());
    }
    Ok(text)
}
fn running(value: &Value) -> Result<()> {
    let o = value.as_object().ok_or("reference link run-state type")?;
    if o.keys()
        .any(|k| !matches!(k.as_str(), "running" | "status" | "singlestep"))
        || o.get("running") != Some(&json!(true))
        || o.get("status") != Some(&json!("running"))
        || o.get("singlestep").is_some_and(|s| s != &json!(false))
    {
        return Err("reference link needs actual non-step running state".into());
    }
    Ok(())
}
struct Transaction<'a> {
    id: u64,
    name: &'a str,
    args: &'a Value,
    reply: &'a Value,
}
fn transactions(trace: &[Value]) -> Result<Vec<Transaction<'_>>> {
    if trace.len() > 16384 {
        return Err("reference link QMP transcript bound".into());
    }
    let mut result = Vec::new();
    let mut pending: Option<(u64, &str, &Value)> = None;
    let mut previous = 0u64;
    let mut events = 0;
    let mut greeting = false;
    for (index, item) in trace.iter().enumerate() {
        let o = item
            .as_object()
            .filter(|o| o.len() == 1)
            .ok_or("reference link transcript envelope")?;
        if let Some(sent) = o.get("sent") {
            let s = sent
                .as_object()
                .filter(|s| s.len() == 3)
                .ok_or("reference link command shape")?;
            let id = s
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id != u64::MAX)
                .ok_or("reference link command id")?;
            let name = s
                .get("execute")
                .and_then(Value::as_str)
                .ok_or("reference link command name")?;
            let args = s
                .get("arguments")
                .filter(|a| a.is_object())
                .ok_or("reference link command args")?;
            let allowed = match name {
                "qmp_capabilities" | "query-status" | "stop" | "cont" => args == &json!({}),
                "human-monitor-command" => {
                    args == &json!({"command-line":"info network"})
                        || args == &json!({"command-line":"info usernet"})
                }
                "set_link" => args == &json!({"name":NIC_NAME,"up":false}),
                "input-send-event" => args
                    .as_object()
                    .is_some_and(|a| a.len() == 1 && a.get("events").is_some_and(Value::is_array)),
                "screendump" => args.as_object().is_some_and(|a| {
                    a.len() == 1 && a.get("filename").is_some_and(Value::is_string)
                }),
                _ => false,
            };
            if !allowed {
                return Err(
                    "reference link transcript includes an unreviewed monitor command".into(),
                );
            }
            if pending.is_some() || previous.checked_add(1) != Some(id) {
                return Err("reference link replay/unpaired command".into());
            }
            previous = id;
            pending = Some((id, name, args));
            events = 0;
        } else if let Some(received) = o.get("received") {
            let r = received.as_object().ok_or("reference link response type")?;
            if r.get("event").is_some() {
                events += 1;
                if pending.is_none()
                    || !r.get("event").is_some_and(Value::is_string)
                    || r.keys()
                        .any(|k| !matches!(k.as_str(), "event" | "data" | "timestamp"))
                    || r.get("data").is_some_and(|v| !v.is_object())
                    || r.get("timestamp").is_some_and(|v| !v.is_object())
                    || events >= EVENT_LIMIT
                {
                    return Err("reference link QMP event bound/order".into());
                }
                continue;
            }
            if r.contains_key("QMP") {
                if index != 0
                    || greeting
                    || r.len() != 1
                    || !r["QMP"].is_object()
                    || pending.is_some()
                    || previous != 0
                {
                    return Err("reference link misplaced/noncanonical QMP greeting".into());
                }
                greeting = true;
                continue;
            }
            let (id, name, args) = pending
                .take()
                .ok_or("reference link response without command")?;
            if r.len() != 2
                || r.get("id").and_then(Value::as_u64) != Some(id)
                || !r.contains_key("return")
            {
                return Err("reference link failed/foreign/noncanonical response".into());
            }
            result.push(Transaction {
                id,
                name,
                args,
                reply: &r["return"],
            });
        } else if !o.contains_key("host_monotonic_ns") || pending.is_some() {
            return Err("reference link unknown transcript item".into());
        }
    }
    if pending.is_some() {
        return Err("reference link truncated command".into());
    }
    Ok(result)
}
/// Independent final transcript check. No caller-selected ID, arbitrary QMP
/// command, link-up retry or second network mutation can qualify this proof.
pub(crate) fn verify_reference_link_down(trace: &[Value]) -> Result<ReferenceLinkDown> {
    let tx = transactions(trace)?;
    let links: Vec<_> = tx
        .iter()
        .enumerate()
        .filter(|(_, t)| t.name == "set_link")
        .collect();
    if links.len() != 1
        || tx.iter().any(|t| {
            matches!(
                t.name,
                "netdev_add" | "netdev_del" | "device_add" | "device_del" | "system_reset"
            )
        })
    {
        return Err(
            "reference link requires exactly one disconnect and no replacement/reset".into(),
        );
    }
    let (index, link) = links[0];
    if index < 2 || index + 2 >= tx.len() {
        return Err("reference link identity/run-state bracket absent".into());
    }
    let window = &tx[index - 2..=index + 2];
    let names = [
        "query-status",
        "human-monitor-command",
        "set_link",
        "human-monitor-command",
        "query-status",
    ];
    for (t, name) in window.iter().zip(names) {
        if t.name != name {
            return Err("reference link command order differs".into());
        }
    }
    if window[0].args != &json!({})
        || window[4].args != &json!({})
        || window[1].args != &json!({"command-line":"info network"})
        || window[3].args != &json!({"command-line":"info network"})
        || link.args != &json!({"name":NIC_NAME,"up":false})
        || link.reply != &json!({})
    {
        return Err("reference link command/ack is not the fixed qualified operation".into());
    }
    running(window[0].reply)?;
    running(window[4].reply)?;
    let before = table(window[1].reply)?;
    let after = table(window[3].reply)?;
    if before != after {
        return Err("reference network identity changed across disconnect".into());
    }
    let digest = |s: &str| {
        Sha256::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    Ok(ReferenceLinkDown {
        device: NIC_NAME,
        backend: "evnet",
        model: "ne2k_isa",
        mac: "02:45:56:52:00:01",
        command_id: link.id,
        before_table_sha256: digest(before),
        after_table_sha256: digest(after),
        qmp_set_link_acknowledged: true,
        guest_phy_notification_claim: false,
    })
}
impl Qmp {
    /// Only the actual retained owned VM's exact queried reference NIC can be
    /// disconnected. Launch arguments and every original I/O cut stay intact.
    pub(crate) fn disconnect_reference_nic(&mut self) -> Result<ReferenceLinkDown> {
        if self
            .transcript
            .iter()
            .any(|r| r.get("sent").and_then(|s| s.get("execute")) == Some(&json!("set_link")))
        {
            return Err("reference link already changed; no retry or restore".into());
        }
        running(&self.execute("query-status", json!({}))?)?;
        table(&self.execute(
            "human-monitor-command",
            json!({"command-line":"info network"}),
        )?)?;
        if self.execute("set_link", json!({"name":NIC_NAME,"up":false}))? != json!({}) {
            return Err("reference link-down ACK noncanonical".into());
        }
        table(&self.execute(
            "human-monitor-command",
            json!({"command-line":"info network"}),
        )?)?;
        running(&self.execute("query-status", json!({}))?)?;
        verify_reference_link_down(&self.transcript)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn network() -> Value {
        json!(format!("{NIC_LINE}\r\n{PEER_LINE}\r\n"))
    }
    fn replies() -> Vec<Value> {
        vec![
            json!({"status":"running","running":true}),
            network(),
            json!({}),
            network(),
            json!({"status":"running","running":true}),
        ]
    }
    fn trace(replies: Vec<Value>) -> Vec<Value> {
        let commands = [
            ("query-status", json!({})),
            (
                "human-monitor-command",
                json!({"command-line":"info network"}),
            ),
            ("set_link", json!({"name":NIC_NAME,"up":false})),
            (
                "human-monitor-command",
                json!({"command-line":"info network"}),
            ),
            ("query-status", json!({})),
        ];
        commands
            .into_iter()
            .zip(replies)
            .enumerate()
            .flat_map(|(i, ((name, args), reply))| {
                [
                    json!({"sent":{"execute":name,"arguments":args,"id":i+1}}),
                    json!({"received":{"return":reply,"id":i+1}}),
                ]
            })
            .collect()
    }
    fn pair() -> (Qmp, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        (
            Qmp {
                reader: BufReader::new(client),
                next: 1,
                transcript: Vec::new(),
                directory: PathBuf::new(),
                deadline: Instant::now() + Duration::from_secs(2),
                origin: Instant::now(),
                pauses: crate::perf_ledger::Ledger::new(),
            },
            server,
        )
    }
    #[test]
    fn actual_qmp_exchange_uses_only_queried_reference_pair_and_one_link_down() {
        let (mut qmp, mut server) = pair();
        let worker = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            for (i, reply) in replies().into_iter().enumerate() {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let sent: Value = serde_json::from_str(&line).unwrap();
                let expected = &trace(replies())[i * 2]["sent"];
                assert_eq!(&sent, expected);
                writeln!(server, "{}", json!({"return":reply,"id":sent["id"]})).unwrap();
            }
        });
        let proof = qmp.disconnect_reference_nic().unwrap();
        assert_eq!(proof, verify_reference_link_down(qmp.transcript()).unwrap());
        assert!(qmp.disconnect_reference_nic().is_err());
        assert_eq!(qmp.transcript.len(), 10);
        worker.join().unwrap();
    }
    #[test]
    fn foreign_id_model_mac_peer_ack_order_replay_and_truncation_never_qualify() {
        let good = trace(replies());
        assert!(verify_reference_link_down(&good).is_ok());
        let mut bad = good.clone();
        bad[4]["sent"]["arguments"]["name"] = json!("evnet");
        assert!(verify_reference_link_down(&bad).is_err());
        let mut bad = good.clone();
        bad[4]["sent"]["arguments"]["up"] = json!(true);
        assert!(verify_reference_link_down(&bad).is_err());
        for wrong in [
            network().as_str().unwrap().replace("ne2k_isa", "e1000"),
            network().as_str().unwrap().replace("00:01", "00:02"),
            network().as_str().unwrap().replace("evnet", "other"),
            format!("{}extra\n", network().as_str().unwrap()),
            "x".repeat(2049),
        ] {
            let mut bad = good.clone();
            bad[3]["received"]["return"] = json!(wrong);
            assert!(verify_reference_link_down(&bad).is_err());
        }
        let mut bad = good.clone();
        bad[5]["received"]["return"] = json!({"ignored":true});
        assert!(verify_reference_link_down(&bad).is_err());
        let mut bad = good.clone();
        bad[5]["received"]["id"] = json!(2);
        assert!(verify_reference_link_down(&bad).is_err());
        let mut bad = good.clone();
        bad.pop();
        assert!(verify_reference_link_down(&bad).is_err());
        let mut bad = good.clone();
        bad.extend([
            json!({"sent":{"execute":"set_link","arguments":{"name":NIC_NAME,"up":true},"id":6}}),
            json!({"received":{"return":{},"id":6}}),
        ]);
        assert!(verify_reference_link_down(&bad).is_err());
        let mut bad = good.clone();
        bad[0]["sent"]["execute"] = json!("stop");
        assert!(verify_reference_link_down(&bad).is_err());
        let mut bad = good.clone();
        bad[9]["received"]["return"] = json!({"status":"paused","running":false});
        assert!(verify_reference_link_down(&bad).is_err());
        for (name, args) in [
            (
                "human-monitor-command",
                json!({"command-line":"set_link ne2k_isa.0 off"}),
            ),
            ("device_del", json!({"id":NIC_NAME})),
            ("system_reset", json!({})),
            ("migrate", json!({"uri":"exec:replacement"})),
        ] {
            let mut bad = good.clone();
            bad.extend([
                json!({"sent":{"execute":name,"arguments":args,"id":6}}),
                json!({"received":{"return":{},"id":6}}),
            ]);
            assert!(verify_reference_link_down(&bad).is_err());
        }
        let greeting = json!({"received":{"QMP":{"version":{}}}});
        let mut with_greeting = good.clone();
        with_greeting.insert(0, greeting.clone());
        assert!(verify_reference_link_down(&with_greeting).is_ok());
        with_greeting.insert(1, greeting.clone());
        assert!(verify_reference_link_down(&with_greeting).is_err());
        let mut bad = good.clone();
        bad.push(greeting);
        assert!(verify_reference_link_down(&bad).is_err());
        for event in [json!({"event":null}), json!({"event":"TEST","return":{}})] {
            let mut bad = good.clone();
            bad.insert(1, json!({"received":event}));
            assert!(verify_reference_link_down(&bad).is_err());
        }
    }
    #[test]
    fn expired_mock_deadline_and_event_flood_refuse_without_link_mutation() {
        let (mut qmp, _) = pair();
        qmp.deadline = Instant::now();
        assert!(qmp.disconnect_reference_nic().is_err());
        assert!(qmp.transcript.is_empty());
        let mut bad = trace(replies());
        for _ in 0..EVENT_LIMIT {
            bad.insert(1, json!({"received":{"event":"TEST"}}));
        }
        assert!(verify_reference_link_down(&bad).is_err());
    }
}
