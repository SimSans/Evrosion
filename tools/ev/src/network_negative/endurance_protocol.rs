//! Kernel-direct scheduling samples for the explicit sustained-use fixture.
//! CPU is Scheduler subtree usage; elapsed time and work labels grant nothing.
use crate::{boot_protocol::canonical_number, build::Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) enum Role {
    Boot,
    Root,
    Shell,
    App,
}
impl Role {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "role=boot" => Ok(Self::Boot),
            "role=root" => Ok(Self::Root),
            "role=shell" => Ok(Self::Shell),
            "role=app" => Ok(Self::App),
            _ => Err("endurance unknown role".into()),
        }
    }
    pub(super) fn index(self) -> usize {
        match self {
            Self::Boot => 0,
            Self::Root => 1,
            Self::Shell => 2,
            Self::App => 3,
        }
    }
    pub(super) fn actor(self) -> usize {
        match self {
            Self::Boot | Self::Root => 0,
            Self::Shell => 1,
            Self::App => 5,
        }
    }
}
pub(super) fn digest(field: &str) -> Result<[u8; 32]> {
    let value = field
        .strip_prefix("image_sha256=")
        .ok_or("endurance image field")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("endurance canonical image digest".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    if out == [0; 32] {
        return Err("endurance missing actual image".into());
    }
    Ok(out)
}
fn header<'a>(text: &'a str, build: &str, prefix: &str, count: usize) -> Result<Vec<&'a str>> {
    let f: Vec<_> = text.split(' ').collect();
    if text.len() > 1024
        || f.len() != count
        || f[0] != prefix
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || build.len() != 64
        || !build
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("endurance diagnostic shape/protocol/build".into());
    }
    Ok(f)
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Cpu {
    pub sample: u64,
    pub role: Role,
    pub identity: (u64, u64),
    pub job: u64,
    pub tick: u64,
    pub cpu: u64,
    pub quota: u64,
    pub period: u64,
    pub window: (u64, u64),
    pub used: u64,
    pub reserved: u64,
    pub remaining: u64,
    pub image: [u8; 32],
}
pub(super) fn cpu(text: &str, build: &str) -> Result<Cpu> {
    let f = header(text, build, "EVROSION_M6_NEGATIVE_CPU", 20)?;
    let role = Role::parse(f[4])?;
    let sample = canonical_number(f[3], "sample")?;
    let keys = [
        "actor",
        "process",
        "thread",
        "job",
        "tick",
        "cpu",
        "quota",
        "period",
        "window_start",
        "window_end",
        "used",
        "reserved",
        "remaining",
    ];
    let n: Vec<_> = f[5..18]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<_>>()?;
    // There are13 numbers after role, then the image and exact scope.
    let image = digest(f[18])?;
    if f[19] != "cpu_scope=subtree" {
        return Err("endurance CPU scope".into());
    }
    let quota = if matches!(role, Role::Boot | Role::Root) {
        256
    } else {
        64
    };
    if !(1..=48).contains(&sample)
        || n[0] != role.actor() as u64
        || n[1..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[4] == u64::MAX
        || n[5] == u64::MAX
        || n[6] != quota
        || n[7] != 256
        || n[8] > n[4]
        || n[9] <= n[4]
        || n[8].checked_add(256) != Some(n[9])
        || n[10].checked_add(n[11]).and_then(|v| v.checked_add(n[12])) != Some(quota)
    {
        return Err("endurance actual identity/quota/window accounting".into());
    }
    Ok(Cpu {
        sample,
        role,
        identity: (n[1], n[2]),
        job: n[3],
        tick: n[4],
        cpu: n[5],
        quota: n[6],
        period: n[7],
        window: (n[8], n[9]),
        used: n[10],
        reserved: n[11],
        remaining: n[12],
        image,
    })
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Work {
    pub role: Role,
    pub identity: (u64, u64),
    pub root: (u64, u64),
    pub endpoint: u64,
    pub ticket: u64,
    pub tick: u64,
    pub request: u64,
    pub image: [u8; 32],
}
pub(super) fn work(text: &str, build: &str) -> Result<Work> {
    let f = header(text, build, "EVROSION_M6_NEGATIVE_WORK", 15)?;
    let role = Role::parse(f[3])?;
    if !matches!(role, Role::Shell | Role::App) || f[4] != "phase=delivered" {
        return Err("endurance actual work phase/role".into());
    }
    let keys = [
        "actor",
        "process",
        "thread",
        "root_process",
        "root_thread",
        "endpoint",
        "ticket",
        "tick",
        "request",
    ];
    let n: Vec<_> = f[5..14]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<_>>()?;
    let request = u64::from_le_bytes(if role == Role::App {
        *b"EVNABUS1"
    } else {
        *b"EVNWORK1"
    });
    if n[0] != role.actor() as u64
        || n[1..7].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[1] == n[3]
        || n[2] == n[4]
        || n[7] == u64::MAX
        || n[8] != request
    {
        return Err("endurance actual work identity/message".into());
    }
    Ok(Work {
        role,
        identity: (n[1], n[2]),
        root: (n[3], n[4]),
        endpoint: n[5],
        ticket: n[6],
        tick: n[7],
        request: n[8],
        image: digest(f[14])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(role: &str, actor: u8, quota: u64) -> String {
        format!(
            "EVROSION_M6_NEGATIVE_CPU protocol=1 build={} sample=1 role={role} actor={actor} process=20 thread=120 job=2 tick=100 cpu=20 quota={quota} period=256 window_start=0 window_end=256 used=10 reserved=0 remaining={} image_sha256={} cpu_scope=subtree",
            "a".repeat(64),
            quota - 10,
            "b".repeat(64)
        )
    }
    #[test]
    fn exact_budget_shape_rejects_counter_forgery_and_noncanonical_fields() {
        let build = "a".repeat(64);
        for (role, actor, quota, index) in [
            ("boot", 0, 256, 0),
            ("root", 0, 256, 1),
            ("shell", 1, 64, 2),
            ("app", 5, 64, 3),
        ] {
            let r = cpu(&row(role, actor, quota), &build).unwrap();
            assert_eq!(r.role.index(), index);
            assert_eq!(r.quota, quota);
        }
        let valid = row("shell", 1, 64);
        for bad in [
            valid.replace("sample=1", "sample=49"),
            valid.replace("sample=1", "sample=01"),
            valid.replace("actor=1", "actor=5"),
            valid.replace("job=2", "job=0"),
            valid.replace("quota=64", "quota=65"),
            valid.replace("remaining=54", "remaining=55"),
            valid.replace("window_end=256", "window_end=255"),
            valid.replace("tick=100", "tick=256"),
            valid.replace("cpu=20", "cpu=18446744073709551615"),
            valid.replace("reserved=0", "reserved=18446744073709551615"),
            valid.replace("subtree", "thread"),
            valid.clone() + " extra=1",
        ] {
            assert!(cpu(&bad, &build).is_err(), "{bad}");
        }
    }
    #[test]
    fn work_is_exact_actual_delivery_to_distinct_root_and_worker() {
        let build = "a".repeat(64);
        let valid = format!(
            "EVROSION_M6_NEGATIVE_WORK protocol=1 build={build} role=app phase=delivered actor=5 process=25 thread=125 root_process=20 root_thread=120 endpoint=50 ticket=4 tick=100 request={} image_sha256={}",
            u64::from_le_bytes(*b"EVNABUS1"),
            "c".repeat(64)
        );
        let w = work(&valid, &build).unwrap();
        assert_eq!(w.role, Role::App);
        assert_eq!(w.identity, (25, 125));
        for bad in [
            valid.replace("phase=delivered", "phase=sent"),
            valid.replace("actor=5", "actor=1"),
            valid.replace("root_process=20", "root_process=25"),
            valid.replace("ticket=4", "ticket=0"),
            valid.replace("role=app", "role=shell"),
            valid.clone() + " extra=1",
        ] {
            assert!(work(&bad, &build).is_err(), "{bad}");
        }
    }
}
