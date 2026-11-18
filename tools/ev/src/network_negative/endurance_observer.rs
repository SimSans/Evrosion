//! Closed coherent CPU groups joined to actual protected work delivery and
//! the retained Root/Shell/App identities. This does not establish GUI, data,
//! stopped hostile ownership or final retirement; the runner must join those.
use super::endurance_protocol::{self as protocol, Cpu, Role, Work};
use crate::build::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct Group {
    pub rows: [Cpu; 4],
    pub line: usize,
}
#[derive(Debug, Serialize)]
pub(super) struct Evidence {
    pub root: (u64, u64),
    pub shell: Option<Work>,
    pub app: Option<Work>,
    pub groups: Vec<Group>,
    pub partial_group: usize,
    closed: bool,
}
#[derive(Debug, Serialize)]
pub(super) struct Threshold {
    pub first_sample: u64,
    pub last_sample: u64,
    pub delta: [u64; 4],
    pub app: (u64, u64),
    pub shell: (u64, u64),
}

pub(super) fn prefix(
    serial: &[u8],
    build: &str,
    images: Option<&[String; 9]>,
) -> Result<Option<Evidence>> {
    if serial.len() > 1024 * 1024 {
        return Err("endurance serial bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "endurance UTF8")?;
    let mut result: Option<Evidence> = None;
    let mut partial: Vec<Cpu> = Vec::new();
    let mut partial_line = 0;
    let mut root_image = None;
    let mut shell_ready = None;
    let mut first_app = None;
    for (position, raw) in text.split_inclusive('\n').enumerate() {
        if !raw.ends_with('\n') {
            break;
        }
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if result.is_some() || c.mode != 0 {
                return Err("endurance missing unique Standalone Root".into());
            }
            root_image = Some(protocol::digest(&format!("image_sha256={}", c.root_image))?);
            result = Some(Evidence {
                root: (c.root_process, c.root_thread),
                shell: None,
                app: None,
                groups: Vec::new(),
                partial_group: 0,
                closed: false,
            });
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let crate::native3_protocol::Event::Critical(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if shell_ready
                .replace((
                    (c.process, c.thread),
                    protocol::digest(&format!("image_sha256={}", c.image))?,
                ))
                .is_some()
            {
                return Err("endurance Shell changed incarnation".into());
            }
        }
        if line.starts_with("EVROSION_M5_NATIVE_ACTION ") {
            let a = crate::native_protocol::action(line, build)?;
            if a.kind == "start" && first_app.is_none() {
                first_app = Some((
                    (a.process, a.thread),
                    protocol::digest(&format!("image_sha256={}", a.image_sha256))?,
                ));
            }
        }
        let telemetry = line.starts_with("EVROSION_M6_NEGATIVE_CPU")
            || line.starts_with("EVROSION_M6_NEGATIVE_WORK");
        if !partial.is_empty() && !line.starts_with("EVROSION_M6_NEGATIVE_CPU ") {
            return Err("endurance coherent CPU group interrupted".into());
        }
        if telemetry {
            let evidence = result
                .as_mut()
                .ok_or("endurance telemetry before actual Root")?;
            if evidence.closed {
                return Err("endurance telemetry after final boundary".into());
            }
            if line.starts_with("EVROSION_M6_NEGATIVE_WORK") {
                let w = protocol::work(line, build)?;
                let expected = if w.role == Role::App {
                    first_app
                } else {
                    shell_ready
                }
                .ok_or("endurance worker lacks actual startup identity")?;
                if w.root != evidence.root || w.identity != expected.0 || w.image != expected.1 {
                    return Err("endurance work belongs to another Root/worker/image".into());
                }
                if let Some(images) = images
                    && w.image
                        != protocol::digest(&format!("image_sha256={}", images[w.role.actor()]))?
                {
                    return Err("endurance work differs from selected source".into());
                }
                let target = if w.role == Role::App {
                    &mut evidence.app
                } else {
                    &mut evidence.shell
                };
                if target.replace(w).is_some() {
                    return Err("endurance replayed protected work delivery".into());
                }
            } else {
                let row = protocol::cpu(line, build)?;
                if row.role.index() != partial.len()
                    || row.sample != evidence.groups.len() as u64 + 1
                {
                    return Err("endurance sample gap/replay/role order".into());
                }
                let expected = match row.role {
                    Role::Boot | Role::Root => (evidence.root, root_image.unwrap()),
                    Role::Shell => shell_ready.ok_or("endurance CPU before actual Shell")?,
                    Role::App => first_app.ok_or("endurance CPU before actual App")?,
                };
                if row.identity != expected.0 || row.image != expected.1 {
                    return Err("endurance sample changed actual process/thread/image".into());
                }
                if let Some(images) = images
                    && row.image
                        != protocol::digest(&format!("image_sha256={}", images[row.role.actor()]))?
                {
                    return Err("endurance sample differs from selected source".into());
                }
                if let Some(first) = partial.first() {
                    if row.tick != first.tick {
                        return Err("endurance CPU group sampled different ticks".into());
                    }
                } else {
                    partial_line = position;
                }
                partial.push(row);
                if partial.len() == 4 {
                    let rows: [Cpu; 4] = std::mem::take(&mut partial)
                        .try_into()
                        .map_err(|_| "endurance group shape")?;
                    let jobs: std::collections::BTreeSet<_> = rows.iter().map(|r| r.job).collect();
                    if jobs.len() != 4
                        || rows[0].cpu < rows[1].cpu
                        || rows[2]
                            .cpu
                            .checked_add(rows[3].cpu)
                            .is_none_or(|v| v > rows[1].cpu)
                    {
                        return Err("endurance Job ancestry or duplicate actual Job".into());
                    }
                    if let Some(old) = evidence.groups.last()
                        && (rows[0].tick <= old.rows[0].tick
                            || rows.iter().zip(&old.rows).any(|(new, old)| {
                                new.job != old.job
                                    || new.cpu < old.cpu
                                    || new.window.0 < old.window.0
                            }))
                    {
                        return Err("endurance reset/decreased cumulative CPU or Job/window".into());
                    }
                    evidence.groups.push(Group {
                        rows,
                        line: partial_line,
                    });
                }
            }
        }
        if line.starts_with("EVROSION_M6_NEGATIVE ") {
            let row = super::records::line(line, build)?;
            if row.kind == 8
                && let Some(evidence) = result.as_mut()
            {
                evidence.closed = true;
            }
        }
        if (line.starts_with("EVROSION_M5_NATIVE_PROFILE ")
            || line.starts_with("EVROSION_M6_LOG_BOUND ")
            || line.starts_with("EVROSION_M6_LOG "))
            && let Some(evidence) = result.as_mut()
        {
            evidence.closed = true;
        }
    }
    if let Some(evidence) = result.as_mut() {
        evidence.partial_group = partial.len();
    }
    Ok(result)
}
impl Evidence {
    pub(super) fn threshold(&self) -> Result<Option<Threshold>> {
        let (Some(app), Some(shell)) = (&self.app, &self.shell) else {
            return Ok(None);
        };
        if app.endpoint == shell.endpoint
            || app.identity.0 == shell.identity.0
            || app.identity.1 == shell.identity.1
        {
            return Err("endurance workers shared protected endpoint or identity".into());
        }
        let after = app.tick.max(shell.tick);
        let mut groups = self.groups.iter().filter(|g| g.rows[0].tick > after);
        let Some(first) = groups.next() else {
            return Ok(None);
        };
        let Some(last) = groups.next_back() else {
            return Ok(None);
        };
        let mut delta = [0; 4];
        for (i, d) in delta.iter_mut().enumerate() {
            *d = last.rows[i]
                .cpu
                .checked_sub(first.rows[i].cpu)
                .ok_or("endurance CPU counter regressed")?;
        }
        if delta[0] <= 262144 || delta[1] <= 65536 || delta[2] <= 16384 || delta[3] == 0 {
            return Ok(None);
        }
        Ok(Some(Threshold {
            first_sample: first.rows[0].sample,
            last_sample: last.rows[0].sample,
            delta,
            app: app.identity,
            shell: shell.identity,
        }))
    }
    pub(super) fn complete(&self) -> Result<Threshold> {
        if !self.closed || self.partial_group != 0 {
            return Err("endurance missing complete final source boundary".into());
        }
        self.threshold()?.ok_or_else(|| {
            "endurance actual CPU deltas did not cross original bounds after both deliveries".into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn groups(number: u64, tick: u64, cpus: [u64; 4]) -> String {
        let mut out = String::new();
        for (i, (role, actor, process, thread, job, image, quota)) in [
            ("boot", 0, 20, 120, 1, "b", 256),
            ("root", 0, 20, 120, 2, "b", 256),
            ("shell", 1, 21, 121, 3, "f", 64),
            ("app", 5, 25, 125, 4, "e", 64),
        ]
        .into_iter()
        .enumerate()
        {
            let start = tick / 256 * 256;
            out.push_str(&format!("EVROSION_M6_NEGATIVE_CPU protocol=1 build={} sample={number} role={role} actor={actor} process={process} thread={thread} job={job} tick={tick} cpu={} quota={quota} period=256 window_start={start} window_end={} used=0 reserved=0 remaining={quota} image_sha256={} cpu_scope=subtree\n","a".repeat(64),cpus[i],start+256,image.repeat(64)));
        }
        out
    }
    fn work(
        role: &str,
        actor: u8,
        process: u64,
        thread: u64,
        endpoint: u64,
        message: &[u8; 8],
        image: &str,
    ) -> String {
        format!(
            "EVROSION_M6_NEGATIVE_WORK protocol=1 build={} role={role} phase=delivered actor={actor} process={process} thread={thread} root_process=20 root_thread=120 endpoint={endpoint} ticket=2 tick=100 request={} image_sha256={}\n",
            "a".repeat(64),
            u64::from_le_bytes(*message),
            image.repeat(64)
        )
    }
    fn fixture() -> String {
        let b = "a".repeat(64);
        let mut text = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={b} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20\nEVROSION_M5_NATIVE_CRITICAL_READY protocol=1 build={b} process=21 thread=121 image_sha256={} tick=90\nEVROSION_M5_NATIVE_ACTION protocol=1 build={b} action=start process=25 thread=125 image_sha256={}\n",
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "f".repeat(64),
            "e".repeat(64)
        );
        text += &work("app", 5, 25, 125, 50, b"EVNABUS1", "e");
        text += &work("shell", 1, 21, 121, 51, b"EVNWORK1", "f");
        text += &groups(1, 2048, [1000, 1000, 100, 100]);
        text += &groups(2, 300032, [300000, 280000, 20000, 50000]);
        text += &format!(
            "EVROSION_M6_NEGATIVE protocol=1 build={b} sequence=1 kind=8 actor=0 process=20 thread=120 tick=400000 call_epoch=0 call=0 endpoint=0 ticket=0 deadline=0 caller_process=0 caller_thread=0 callee_process=0 callee_thread=0 opcode=0 status=0 length=0 value=0 request=0 payload_sha256={} image_sha256={}\n",
            "0".repeat(64),
            "b".repeat(64)
        );
        text
    }
    #[test]
    fn actual_scoped_group_deltas_require_both_deliveries_and_live_original_jobs() {
        let b = "a".repeat(64);
        let s = fixture();
        let actual = prefix(s.as_bytes(), &b, None).unwrap().unwrap();
        let done = actual.complete().unwrap();
        assert_eq!(done.delta, [299000, 279000, 19900, 49900]);
        assert_eq!(done.app, (25, 125));
        assert_eq!(done.shell, (21, 121));
        let too_late = s.replace("ticket=2 tick=100", "ticket=2 tick=310000");
        assert!(
            prefix(too_late.as_bytes(), &b, None)
                .unwrap()
                .unwrap()
                .complete()
                .is_err()
        );
        let elapsed_only = s
            .replace("cpu=300000", "cpu=2000")
            .replace("cpu=280000", "cpu=2000")
            .replace("cpu=20000", "cpu=200")
            .replace("cpu=50000", "cpu=200");
        assert!(
            prefix(elapsed_only.as_bytes(), &b, None)
                .unwrap()
                .unwrap()
                .complete()
                .is_err()
        );
    }
    #[test]
    fn changed_source_identity_job_counter_or_incoherent_group_refuses() {
        let b = "a".repeat(64);
        let s = fixture();
        for bad in [
            s.replace("sample=2", "sample=1"),
            s.replace("cpu=50000", "cpu=50"),
            s.replace("role=app actor=5 process=25", "role=app actor=5 process=26"),
            s.replace(
                "role=root actor=0 process=20 thread=120 job=2",
                "role=root actor=0 process=20 thread=120 job=1",
            ),
            s.replace("sample=2 role=shell", "sample=2 role=root"),
            s.replace("ticket=2 tick=100 request=", "ticket=0 tick=100 request="),
            s.replace("role=app phase=delivered", "role=shell phase=delivered"),
        ] {
            assert!(prefix(bad.as_bytes(), &b, None).is_err(), "{bad}");
        }
        let images = std::array::from_fn(|_| "1".repeat(64));
        assert!(prefix(s.as_bytes(), &b, Some(&images)).is_err());
        let repeated = s.replace(
            &groups(1, 2048, [1000, 1000, 100, 100]),
            &(groups(1, 2048, [1000, 1000, 100, 100])
                + &work("app", 5, 25, 125, 50, b"EVNABUS1", "e")),
        );
        assert!(prefix(repeated.as_bytes(), &b, None).is_err());
    }
    #[test]
    fn truncated_or_post_final_samples_cannot_close_scope() {
        let b = "a".repeat(64);
        let s = fixture();
        let without_last = s
            .lines()
            .filter(|l| !l.contains("kind=8"))
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        assert!(
            prefix(without_last.as_bytes(), &b, None)
                .unwrap()
                .unwrap()
                .complete()
                .is_err()
        );
        let missing_app = s
            .lines()
            .filter(|l| !l.contains("sample=2 role=app"))
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        assert!(prefix(missing_app.as_bytes(), &b, None).is_err());
        let after = s + &groups(3, 400128, [400000, 380000, 30000, 60000]);
        assert!(prefix(after.as_bytes(), &b, None).is_err());
    }
}
