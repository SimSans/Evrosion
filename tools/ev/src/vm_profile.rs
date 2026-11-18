//! Host half of the explicitly reviewed developer-VM source profile.
//! This validates the actual executable and launch arguments, independently of
//! the reproducible guest catalogue. A trusted host remains part of this VM
//! qualification; neither a digest nor a CPUID label authenticates a hostile host.
use crate::build::{self, Result};
use serde::Serialize;
use std::path::Path;

const QEMU: &str = "0cd4112a8f0cb891eb7c10e8df38c9dfeec8c7389bb22db6aa425f0d6fe733dc";
const REVIEW: &str = "409de274e013287877b7a2762075c65e4ff535cfea624ea0ee3d5b7e4ffeba9d";
pub(crate) const NIC: &str = "ne2k_isa,netdev=evnet,mac=02:45:56:52:00:01,iobase=0x300,irq=9";
pub(crate) const NETDEV: &str = "user,id=evnet,ipv6=off";
pub(crate) const RTC: &str = "base=utc,clock=rt,driftfix=none";

#[derive(Serialize)]
pub(crate) struct Qualification {
    schema: u16,
    profile: &'static str,
    executable_sha256: String,
    reviewed_package_receipt_sha256: &'static str,
    trusted_host_assumption: &'static str,
    entropy_path: &'static str,
    deterministic_or_replay_mode: bool,
    utc_provider_qualified: bool,
    entropy_feature_expected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    fault_injection: Option<&'static str>,
}

/// No generic argument pass-through: unknown switches and alternative machine,
/// CPU, randomness, replay, plugin, config and acceleration inputs refuse before
/// starting a guest. The caller records and executes these exact arguments.
pub(crate) fn arguments(arguments: &[String]) -> Result<()> {
    arguments_for_cpu(arguments, "max")
}
fn arguments_for_cpu(arguments: &[String], cpu: &str) -> Result<()> {
    arguments_profile(arguments, cpu, false, false)
}
pub(crate) fn workspace_arguments(arguments: &[String]) -> Result<()> {
    arguments_profile(arguments, "max", true, false)
}
pub(crate) fn workspace_restart_arguments(arguments: &[String]) -> Result<()> {
    arguments_profile(arguments, "max", true, true)
}
const WORKSPACE_DISK: &str = "ide-hd,drive=evdata,bus=evpio.0,unit=0,serial=EVROSION-M8-WORK    ,logical_block_size=512,physical_block_size=512";
const LEGACY_DISK: &str = "ide-hd,drive=evdata,bus=evpio.0,unit=0,serial=EVROSION-M3-PIO,logical_block_size=512,physical_block_size=512";
fn arguments_profile(
    arguments: &[String],
    cpu: &str,
    workspace: bool,
    guest_restart: bool,
) -> Result<()> {
    let mut singleton = std::collections::BTreeMap::new();
    let mut devices = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let key = arguments[index].as_str();
        if matches!(key, "-nodefaults" | "-no-user-config" | "-no-reboot" | "-S") {
            if singleton.insert(key, "").is_some() {
                return Err("duplicate VM switch".into());
            }
            index += 1;
            continue;
        }
        if !matches!(
            key,
            "-machine"
                | "-cpu"
                | "-smp"
                | "-m"
                | "-display"
                | "-monitor"
                | "-nic"
                | "-device"
                | "-chardev"
                | "-drive"
                | "-boot"
                | "-qmp"
                | "-netdev"
                | "-rtc"
        ) {
            return Err(format!("unqualified VM argument: {key}"));
        }
        let value = arguments
            .get(index + 1)
            .ok_or("VM argument has no value")?
            .as_str();
        if value.is_empty() || value.starts_with('-') {
            return Err("invalid VM argument value".into());
        }
        if key == "-device" {
            if value.starts_with("ide-hd,drive=evdata,")
                && value
                    != if workspace {
                        WORKSPACE_DISK
                    } else {
                        LEGACY_DISK
                    }
            {
                return Err("VM disk serial/source profile differs".into());
            }
            if !matches!(
                value,
                "VGA"
                    | "isa-debug-exit,iobase=0xf4,iosize=0x04"
                    | "isa-serial,chardev=com1"
                    | "isa-ide,id=evpio,iobase=0x1e8,iobase2=0x3ee,irq=10"
                    | "ide-hd,drive=evdata,bus=evpio.0,unit=0,serial=EVROSION-M3-PIO,logical_block_size=512,physical_block_size=512"
            ) && value != NIC
                && !(workspace && value == WORKSPACE_DISK)
            {
                return Err("unqualified VM device".into());
            }
            if devices.contains(&value) {
                return Err("duplicate VM device".into());
            }
            devices.push(value);
        } else if key != "-drive" && singleton.insert(key, value).is_some() {
            return Err("duplicate VM argument".into());
        }
        index += 2;
    }
    for (key, expected) in [
        ("-machine", "q35,accel=tcg"),
        ("-cpu", cpu),
        ("-smp", "1"),
        ("-m", "256M"),
        ("-nodefaults", ""),
        ("-no-user-config", ""),
        ("-no-reboot", ""),
        ("-S", ""),
        ("-monitor", "none"),
        ("-nic", "none"),
        ("-netdev", NETDEV),
        ("-rtc", RTC),
    ] {
        if key == "-no-reboot" && guest_restart {
            if singleton.contains_key(key) {
                return Err("guest restart profile requires reboot to remain enabled".into());
            }
            continue;
        }
        if singleton.get(key).copied() != Some(expected) {
            return Err(format!("VM source profile requires exact {key}"));
        }
    }
    if workspace && !devices.contains(&WORKSPACE_DISK) {
        return Err("workspace disk profile missing".into());
    }
    if !devices.contains(&NIC) {
        return Err("VM network device missing".into());
    }
    if !matches!(
        singleton.get("-display").copied(),
        Some("none" | "gtk,gl=off")
    ) {
        return Err("VM display profile differs".into());
    }
    Ok(())
}

pub(crate) fn qualify(executable: &Path, launch: &[String]) -> Result<Qualification> {
    arguments(launch)?;
    qualify_checked(executable, false)
}
pub(crate) fn qualify_workspace(executable: &Path, launch: &[String]) -> Result<Qualification> {
    workspace_arguments(launch)?;
    qualify_checked(executable, true)
}
pub(crate) fn qualify_workspace_restart(
    executable: &Path,
    launch: &[String],
) -> Result<Qualification> {
    workspace_restart_arguments(launch)?;
    let mut qualification = qualify_checked(executable, true)?;
    qualification.profile = "evrosion.vm.tcg-reviewed-m8-guest-restart.v1";
    Ok(qualification)
}
fn qualify_checked(executable: &Path, workspace: bool) -> Result<Qualification> {
    let executable_sha256 = build::hash_file(executable)?;
    if executable_sha256 != QEMU {
        return Err("QEMU executable lacks this VM source qualification".into());
    }
    Ok(Qualification {
        schema: 1,
        profile: if workspace {
            "evrosion.vm.tcg-reviewed-m8-disk.v1"
        } else {
            "evrosion.vm.tcg-reviewed-gnutls-random.v1"
        },
        executable_sha256,
        reviewed_package_receipt_sha256: REVIEW,
        trusted_host_assumption: "Owner-controlled host OS, dynamic loader and system crypto libraries remain trusted; this check is not host attestation",
        entropy_path: "TCG RDRAND -> qemu_guest_getrandom -> GNUTLS_RND_RANDOM; guest CF check -> private ChaCha20",
        deterministic_or_replay_mode: false,
        // The elapsed RTC/shim does not implement/qualify a guest UTC adapter.
        utc_provider_qualified: false,
        entropy_feature_expected: true,
        fault_injection: None,
    })
}
/// Explicit negative configuration; it can never qualify a positive entropy
/// path. Every argument except this one absent CPU feature remains identical.
pub(crate) fn qualify_missing_entropy(
    executable: &Path,
    launch: &[String],
) -> Result<Qualification> {
    arguments_for_cpu(launch, "max,rdrand=off")?;
    let executable_sha256 = build::hash_file(executable)?;
    if executable_sha256 != QEMU {
        return Err("negative QEMU executable differs from reviewed binary".into());
    }
    Ok(Qualification {
        schema: 1,
        profile: "evrosion.vm.tcg-rdrand-absent-negative.v1",
        executable_sha256,
        reviewed_package_receipt_sha256: REVIEW,
        trusted_host_assumption: "Same owner-controlled reviewed host/loader assumption; deliberate CPU feature absence is not an entropy qualification",
        entropy_path: "RDRAND deliberately absent; Root must refuse before instruction/seed acquisition",
        deterministic_or_replay_mode: false,
        utc_provider_qualified: false,
        entropy_feature_expected: false,
        fault_injection: Some("exact -cpu max,rdrand=off"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn launch() -> Vec<String> {
        [
            "-machine",
            "q35,accel=tcg",
            "-cpu",
            "max",
            "-smp",
            "1",
            "-m",
            "256M",
            "-nodefaults",
            "-no-user-config",
            "-no-reboot",
            "-S",
            "-display",
            "none",
            "-monitor",
            "none",
            "-nic",
            "none",
            "-device",
            NIC,
            "-netdev",
            NETDEV,
            "-rtc",
            RTC,
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
    #[test]
    fn workspace_disk_serial_is_a_separate_profile() {
        let mut workspace = launch();
        workspace.extend(["-device".into(), WORKSPACE_DISK.into()]);
        workspace_arguments(&workspace).unwrap();
        assert!(arguments(&workspace).is_err());
        let mut legacy = launch();
        legacy.extend(["-device".into(), LEGACY_DISK.into()]);
        arguments(&legacy).unwrap();
        assert!(workspace_arguments(&legacy).is_err());
    }
    #[test]
    fn guest_restart_is_an_explicit_separate_launch_profile() {
        let mut workspace = launch();
        workspace.extend(["-device".into(), WORKSPACE_DISK.into()]);
        assert!(workspace_restart_arguments(&workspace).is_err());
        workspace.retain(|arg| arg != "-no-reboot");
        workspace_restart_arguments(&workspace).unwrap();
        assert!(workspace_arguments(&workspace).is_err());
        workspace.extend(["-machine".into(), "q35,accel=kvm".into()]);
        assert!(workspace_restart_arguments(&workspace).is_err());
    }
    #[test]
    fn source_profile_rejects_determinism_plugins_configs_and_alternate_backends() {
        arguments(&launch()).unwrap();
        for extra in [
            vec!["-seed", "7"],
            vec!["-icount", "shift=auto,rr=replay,rrfile=x"],
            vec!["-readconfig", "other"],
            vec!["-plugin", "other"],
            vec!["-accel", "kvm"],
            vec!["-machine", "q35,accel=kvm"],
            vec!["-cpu", "max,rdrand=off"],
            vec!["-enable-kvm"],
            vec!["-global", "anything"],
            vec!["-loadvm", "old"],
        ] {
            let mut candidate = launch();
            candidate.extend(extra.into_iter().map(String::from));
            assert!(arguments(&candidate).is_err());
        }
        let mut candidate = launch();
        candidate.retain(|arg| arg != "-no-user-config");
        assert!(arguments(&candidate).is_err());
        let mut candidate = launch();
        let value = candidate.iter().position(|arg| arg == "-cpu").unwrap() + 1;
        candidate[value] = "host".into();
        assert!(arguments(&candidate).is_err());
    }
    #[test]
    fn missing_entropy_is_a_separate_exact_negative_cpu_profile() {
        assert!(arguments_for_cpu(&launch(), "max,rdrand=off").is_err());
        let mut negative = launch();
        let at = negative.iter().position(|arg| arg == "-cpu").unwrap() + 1;
        negative[at] = "max,rdrand=off".into();
        arguments_for_cpu(&negative, "max,rdrand=off").unwrap();
        assert!(arguments(&negative).is_err());
        for cpu in [
            "max,rdrand=on",
            "max,rdrand=off,rdseed=off",
            "host",
            "max,-rdrand",
        ] {
            negative[at] = cpu.into();
            assert!(arguments_for_cpu(&negative, "max,rdrand=off").is_err());
        }
    }
    #[test]
    fn elapsed_source_requires_exact_rtc_and_a_single_halted_start() {
        let mut candidate = launch();
        candidate.retain(|arg| arg != "-S");
        assert!(arguments(&candidate).is_err());
        let mut candidate = launch();
        candidate.push("-S".into());
        assert!(arguments(&candidate).is_err());
        for rtc in [
            "base=utc,clock=host",
            "base=utc,clock=rt,driftfix=slew",
            "base=localtime,clock=rt,driftfix=none",
        ] {
            let mut candidate = launch();
            let index = candidate.iter().position(|arg| arg == "-rtc").unwrap() + 1;
            candidate[index] = rtc.into();
            assert!(arguments(&candidate).is_err());
        }
        arguments(&launch()).unwrap();
    }
}
