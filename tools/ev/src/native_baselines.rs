//! Actual bounded Native memory observations. Reserved input and virtual image
//! may alias; only disjoint reserved-input/usable-pool ownership is added.
use crate::{
    boot_protocol::canonical_number,
    build::{self, Manifest, Result},
};
use serde_json::{Value, json};
use std::{fs, path::Path};
fn fields<'a>(line: &'a str, build: &str) -> Result<Vec<&'a str>> {
    let fields: Vec<_> = line.split(' ').collect();
    if line.len() > 768
        || fields.len() < 3
        || fields[1] != "protocol=1"
        || fields[2] != format!("build={build}")
    {
        return Err("Native memory malformed/wrong-build observation".into());
    }
    Ok(fields)
}
pub(crate) fn line(line: &str, build: &str) -> Result<()> {
    let f = fields(line, build)?;
    if f[0] == "EVROSION_M5_NATIVE_MEMORY" && f.len() == 6 {
        if !matches!(f[3], "phase=before" | "phase=held" | "phase=after") {
            return Err("Native memory phase unknown".into());
        }
        let total = canonical_number(f[4], "total_frames")?;
        let remaining = canonical_number(f[5], "remaining_frames")?;
        if total == 0 || remaining > total || total.checked_mul(4096).is_none() {
            return Err("Native memory impossible arena counts".into());
        }
    } else if f[0] == "EVROSION_M5_NATIVE_KERNEL_MEMORY" && f.len() == 7 {
        let ps = canonical_number(f[3], "physical_start")?;
        let pe = canonical_number(f[4], "physical_end")?;
        let vs = canonical_number(f[5], "virtual_start")?;
        let ve = canonical_number(f[6], "virtual_end")?;
        if ps == 0
            || pe <= ps
            || pe > (1u64 << 52)
            || pe.checked_add(4095).is_none()
            || vs < 0xffff_8000_0000_0000
            || ve <= vs
        {
            return Err("Native memory invalid validated Kernel ranges".into());
        }
    } else {
        return Err("Native memory fields/prefix differ".into());
    }
    Ok(())
}
pub(crate) fn memory(serial: &[u8], build: &str) -> Result<Value> {
    if serial.len() > 1024 * 1024 || !serial.ends_with(b"\n") {
        return Err("Native memory serial oversized/truncated".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native memory serial notUTF8")?;
    let mut kernel = None;
    let mut snapshots = Vec::new();
    let mut footer = false;
    for raw in text.lines() {
        if raw.starts_with("EVROSION_M5_NATIVE ") || raw.starts_with("EVROSION_M5_NATIVE_RECOVERY ")
        {
            footer = true;
        }
        if !raw.starts_with("EVROSION_M5_NATIVE_MEMORY ")
            && !raw.starts_with("EVROSION_M5_NATIVE_KERNEL_MEMORY ")
        {
            continue;
        }
        if footer {
            return Err("Native memory observation follows final retirement footer".into());
        }
        line(raw, build)?;
        let f: Vec<_> = raw.split(' ').collect();
        if f[0] == "EVROSION_M5_NATIVE_KERNEL_MEMORY" {
            if kernel.is_some() || !snapshots.is_empty() {
                return Err("Native Kernel range duplicate/out-of-order".into());
            }
            kernel = Some((
                canonical_number(f[3], "physical_start")?,
                canonical_number(f[4], "physical_end")?,
                canonical_number(f[5], "virtual_start")?,
                canonical_number(f[6], "virtual_end")?,
            ));
        } else {
            let expected = ["phase=before", "phase=held", "phase=after"]
                .get(snapshots.len())
                .ok_or("Native memory snapshot duplicate/overbudget")?;
            if kernel.is_none() || f[3] != *expected {
                return Err("Native memory snapshot order differs".into());
            }
            snapshots.push((
                canonical_number(f[4], "total_frames")?,
                canonical_number(f[5], "remaining_frames")?,
            ));
        }
    }
    let (ps, pe, vs, ve) = kernel.ok_or("Native actual Kernel ranges absent")?;
    if snapshots.len() != 3
        || snapshots.iter().any(|s| s.0 != snapshots[0].0)
        || snapshots[0].1 != snapshots[2].1
        || snapshots[1].1 >= snapshots[0].1
    {
        return Err("Native memory lacks held ownership/exact final allocator return".into());
    }
    let total = snapshots[0].0;
    let held = (total - snapshots[1].1) * 4096;
    let native_held = (snapshots[0].1 - snapshots[1].1) * 4096;
    let input_pages = ((pe + 4095) & !4095) - (ps & !4095);
    let known = input_pages
        .checked_add(held)
        .ok_or("Native memory subtotal overflow")?;
    Ok(
        json!({"schema":1,"scope":"actual Native reference VM before final physical retirement; no peak or exact whole-machine RAM claim","arena":{"total_frames":total,"before_remaining_frames":snapshots[0].1,"held_remaining_frames":snapshots[1].1,"after_remaining_frames":snapshots[2].1,"live_allocated_bytes":held,"native_held_bytes":native_held,"exact_final_return":true},"kernel":{"physical_input_start":ps,"physical_input_end":pe,"physical_input_payload_bytes":pe-ps,"physical_input_reserved_page_bytes":input_pages,"virtual_start":vs,"virtual_end":ve,"virtual_image_span_bytes":ve-vs,"source":"validated current BootInfo contract; temporary trusted loader EXC0001"},"known_disjoint_input_and_arena_bytes":known,"coverage":"Input is reserved and the allocator uses only validated Usable regions. Virtual Kernel mappings may alias retained input and are not added again. Kernel BSS/COW pages, loader stacks/page tables and other firmware-reserved allocations are not independently attributed; Job hierarchy is never added to physical arena bytes."}),
    )
}
pub(crate) fn retain(
    root: &Path,
    manifest: &Manifest,
    serial: &[u8],
    directory: &Path,
) -> Result<Value> {
    let mut value = memory(serial, &manifest.build_id)?;
    let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
    let image = build::verify_artifact(&root.join("build/m0"), &manifest.image)?;
    let kernel_bytes = fs::metadata(kernel).map_err(|e| e.to_string())?.len();
    if value["kernel"]["physical_input_payload_bytes"].as_u64() != Some(kernel_bytes) {
        return Err(
            "Native actual retained Kernel input extent differs from exact executed ELF bytes"
                .into(),
        );
    }
    let command: Value = serde_json::from_slice(
        &fs::read(directory.join("boot/run-001/qemu-command.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let transcript: Value = serde_json::from_slice(
        &fs::read(directory.join("boot/run-001/qmp-transcript.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    value["resident_ram_interval"] = resident_interval(&value, &command, &transcript)?;
    value["artifacts"] = json!({"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,"kernel_elf_bytes":kernel_bytes,"kernel_sha256":manifest.kernel.sha256,"uefi_image_bytes":fs::metadata(image).map_err(|e|e.to_string())?.len(),"image_sha256":manifest.image.sha256});
    crate::storage::json_new(&directory.join("memory-image-baseline.json"), &value)?;
    Ok(value)
}
fn resident_interval(value: &Value, command: &Value, transcript: &Value) -> Result<Value> {
    let args: Vec<_> = command
        .get("arguments")
        .and_then(Value::as_array)
        .ok_or("Native RAM bound lacks actual QEMU argv")?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| "Native QEMU argv notstring".to_string())
        })
        .collect::<Result<_>>()?;
    let positions: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (*s == "-m").then_some(i))
        .collect();
    if positions.len() != 1
        || args.get(positions[0] + 1) != Some(&"256M")
        || args.iter().any(|s| {
            matches!(*s, "-object" | "-mem-path" | "-numa")
                || [
                    "memory-backend",
                    "pc-dimm",
                    "nvdimm",
                    "virtio-mem",
                    "maxmem=",
                    "slots=",
                ]
                .iter()
                .any(|needle| s.contains(needle))
        })
    {
        return Err("Native RAM bound requires exact recorded256M without additional memory/hotplug backends".into());
    }
    let exchanges = transcript
        .get("exchanges")
        .and_then(Value::as_array)
        .ok_or("Native RAM bound lacks owned QMP transcript")?;
    for exchange in exchanges {
        if let Some(sent) = exchange.get("sent") {
            let operation = sent
                .get("execute")
                .and_then(Value::as_str)
                .ok_or("Native QMP operation absent")?;
            if !matches!(
                operation,
                "qmp_capabilities"
                    | "query-status"
                    | "stop"
                    | "cont"
                    | "screendump"
                    | "input-send-event"
            ) {
                return Err("Native RAM bound refuses unaccounted QMP operation".into());
            }
        }
    }
    let word = |v: &Value, key: &str| {
        v.get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("Native RAM bound missing{key}"))
    };
    let arena = &value["arena"];
    let total = word(arena, "total_frames")?;
    let remaining = word(arena, "held_remaining_frames")?;
    let base = 256u64 * 1024 * 1024;
    let total_bytes = total
        .checked_mul(4096)
        .ok_or("Native RAM bound overflows")?;
    let free = remaining
        .checked_mul(4096)
        .ok_or("Native RAM freebytes overflow")?;
    let lower = word(value, "known_disjoint_input_and_arena_bytes")?;
    let upper = base
        .checked_sub(free)
        .ok_or("Native RAM freebytes exceed baseRAM")?;
    if total_bytes > base
        || remaining > total
        || lower > upper
        || word(&value["kernel"], "physical_input_end")? > base
    {
        return Err("Native RAM observed counts/ranges exceed recorded baseRAM envelope".into());
    }
    Ok(
        json!({"scope":"actual held-point Kernel/system resident RAM interval within recorded fixed-base reference VM; no peak or exact RSS claim","base_ram_bytes":base,"held_lower_bytes":lower,"held_upper_bytes":upper,"unattributed_reserved_envelope_bytes":upper-lower,"method":"lower: disjoint reserved Kernel input plus live Usable arena; upper: configured baseRAM minus all actual free Usable frames. Upper includes Kernel BSS/COW, loader stacks/page tables, firmware and address holes; these cannot be silently treated as exact OS allocation. Virtual image span and hierarchical Job charges are never added.","no_extra_memory_backends_or_qmp_memory_mutation":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> String {
        format!(
            "EVROSION_M5_NATIVE_KERNEL_MEMORY protocol=1 build=a physical_start=4096 physical_end=12288 virtual_start={} virtual_end={}\nEVROSION_M5_NATIVE_MEMORY protocol=1 build=a phase=before total_frames=100 remaining_frames=98\nEVROSION_M5_NATIVE_MEMORY protocol=1 build=a phase=held total_frames=100 remaining_frames=60\nEVROSION_M5_NATIVE_MEMORY protocol=1 build=a phase=after total_frames=100 remaining_frames=98\n",
            0xffff_ffff_8000_0000u64, 0xffff_ffff_8001_0000u64
        )
    }
    #[test]
    fn aliases_and_hierarchical_jobs_cannot_be_added_twice_to_physical_subtotal() {
        let result = memory(fixture().as_bytes(), "a").unwrap();
        assert_eq!(result["arena"]["live_allocated_bytes"], 40 * 4096);
        assert_eq!(result["arena"]["native_held_bytes"], 38 * 4096);
        assert_eq!(result["known_disjoint_input_and_arena_bytes"], 42 * 4096);
        assert_eq!(result["kernel"]["virtual_image_span_bytes"], 65536);
    }
    #[test]
    fn recorded_base_ram_bounds_all_unattributed_reservations_and_rejects_extra_memory() {
        let value = memory(fixture().as_bytes(), "a").unwrap();
        let command = json!({"arguments":["-m","256M","-device","VGA"]});
        let qmp = json!({"exchanges":[{"sent":{"execute":"query-status"}}]});
        let interval = resident_interval(&value, &command, &qmp).unwrap();
        assert_eq!(interval["held_lower_bytes"], 42 * 4096);
        assert_eq!(
            interval["held_upper_bytes"],
            256u64 * 1024 * 1024 - 60 * 4096
        );
        for args in [
            json!(["-m", "128M"]),
            json!(["-m", "256M", "-m", "256M"]),
            json!([
                "-m",
                "256M",
                "-object",
                "memory-backend-ram,id=extra,size=1M"
            ]),
            json!(["-m", "256M", "-device", "pc-dimm"]),
            json!(["-m", "256M,maxmem=512M"]),
        ] {
            assert!(resident_interval(&value, &json!({"arguments":args}), &qmp).is_err());
        }
        assert!(
            resident_interval(
                &value,
                &command,
                &json!({"exchanges":[{"sent":{"execute":"device_add"}}]})
            )
            .is_err()
        );
        let mut impossible = value.clone();
        impossible["arena"]["total_frames"] = json!(100000);
        assert!(resident_interval(&impossible, &command, &qmp).is_err());
        impossible = value;
        impossible["known_disjoint_input_and_arena_bytes"] = json!(256u64 * 1024 * 1024);
        assert!(resident_interval(&impossible, &command, &qmp).is_err());
    }
    #[test]
    fn missing_reordered_replayed_wrong_build_leaked_and_impossible_snapshots_refuse() {
        let text = fixture();
        for bad in [
            text.replace("phase=before", "phase=after"),
            text.replace("physical_end=12288", "physical_end=4503599627370497"),
            text.replace("phase=after", "phase=held"),
            text.replace("phase=held total_frames=100", "phase=held total_frames=99"),
            text.replace(
                "phase=after total_frames=100 remaining_frames=98",
                "phase=after total_frames=100 remaining_frames=97",
            ),
            text.replace("remaining_frames=60", "remaining_frames=101"),
            text.replace(
                "phase=held total_frames=100 remaining_frames=60",
                "phase=held total_frames=100 remaining_frames=98",
            ),
            format!("{text}{}", text.lines().last().unwrap()),
            text.trim_end().into(),
            text.replace("build=a", "build=b"),
        ] {
            assert!(memory(bad.as_bytes(), "a").is_err(), "{bad}");
        }
    }
}
