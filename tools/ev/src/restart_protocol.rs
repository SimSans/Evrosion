//! Actual Kernel-authenticated Root restart intent. Intent grants neither
//! reset authority nor permission to relaunch without full checked retirement.
use crate::{boot_protocol::canonical_number, build::Result};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Intent {
    pub root_process: u64,
    pub root_thread: u64,
    pub endpoint: u64,
    pub ticket: u64,
    pub tick: u64,
    pub generation: u32,
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn line(line: &str, build: &str) -> Result<Intent> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 10
        || !digest(build)
        || f[0] != "EVROSION_M6_RESTART"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || f[8] != "mode=1"
    {
        return Err("restart intent wrong shape/build/protocol/mode".into());
    }
    let nonzero = |at, name| -> Result<u64> {
        let n = canonical_number(f[at], name)?;
        if n == 0 || n == u64::MAX {
            Err(format!("restart intent invalid {name}"))
        } else {
            Ok(n)
        }
    };
    let generation =
        u32::try_from(nonzero(9, "generation")?).map_err(|_| "restart generation width")?;
    let tick = canonical_number(f[7], "tick")?;
    if generation == u32::MAX || tick == u64::MAX {
        return Err("restart exhausted generation/tick".into());
    }
    Ok(Intent {
        root_process: nonzero(3, "root_process")?,
        root_thread: nonzero(4, "root_thread")?,
        endpoint: nonzero(5, "endpoint")?,
        ticket: nonzero(6, "ticket")?,
        tick,
        generation,
    })
}
/// Parse only complete bounded output and join to the actual current Root.
/// Selected generation must subsequently be read from the durable owned disk.
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Intent>> {
    if serial.len() > 1024 * 1024 {
        return Err("restart serial bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "restart serial UTF8")?;
    let mut root = None;
    let mut out = Vec::new();
    for raw in text.split_inclusive('\n') {
        if raw.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if !raw.ends_with('\n') {
                return Err("restart truncated actual Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(raw.trim_end_matches(['\r', '\n']), build)?
            else {
                unreachable!()
            };
            if root.replace(c).is_some() {
                return Err("restart duplicate actual Root".into());
            }
        }
        if raw.starts_with("EVROSION_M6_RESTART") {
            if !raw.ends_with('\n') {
                return Err("restart truncated intent".into());
            }
            let i = line(raw.trim_end_matches(['\r', '\n']), build)?;
            let root = root.as_ref().ok_or("restart before actual Root identity")?;
            if (i.root_process, i.root_thread) != (root.root_process, root.root_thread)
                || !out.is_empty()
            {
                return Err("restart foreign Root/replayed intent".into());
            }
            out.push(i);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> String {
        format!(
            "EVROSION_M6_RESTART protocol=1 build={} root_process=20 root_thread=120 endpoint=7 ticket=91 tick=100 mode=1 generation=2",
            "a".repeat(64)
        )
    }
    #[test]
    fn exact_intent_refuses_wrong_protocol_build_mode_width_and_noncanonical_numbers() {
        let build = "a".repeat(64);
        let g = good();
        assert_eq!(line(&g, &build).unwrap().generation, 2);
        for bad in [
            g.replace("protocol=1", "protocol=2"),
            g.replace("mode=1", "mode=0"),
            g.replace("mode=1", "mode=2"),
            g.replace("generation=2", "generation=0"),
            g.replace("generation=2", "generation=4294967295"),
            g.replace("generation=2", "generation=4294967296"),
            g.replace("ticket=91", "ticket=0"),
            g.replace("root_thread=120", "root_thread=0120"),
            g.replace("tick=100", "tick=18446744073709551615"),
            g.clone() + " extra=1",
            g.replace(" endpoint=7", "  endpoint=7"),
        ] {
            assert!(line(&bad, &build).is_err(), "{bad}");
        }
        assert!(line(&g, &"b".repeat(64)).is_err());
    }
    #[test]
    fn missing_or_truncated_actual_root_never_becomes_an_intent() {
        let build = "a".repeat(64);
        assert!(records(format!("{}\n", good()).as_bytes(), &build).is_err());
        assert!(records(good().as_bytes(), &build).is_err());
        assert!(records(b"", &build).unwrap().is_empty());
    }
}
