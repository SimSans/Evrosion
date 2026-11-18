//! Adversarial parser fixtures derived from the real two window codecs. No
//! record created here is represented as an actual Kernel or VM execution.
use super::*;
use ev_net_driver::{
    control,
    protocol::{self, Window},
};
use ev_userspace_contract::syscall;

struct Memory([u8; 4096]);
impl Window for Memory {
    type Error = ();
    fn read(&mut self, n: usize) -> core::result::Result<u8, ()> {
        self.0.get(n).copied().ok_or(())
    }
    fn write(&mut self, n: usize, b: u8) -> core::result::Result<(), ()> {
        *self.0.get_mut(n).ok_or(())? = b;
        Ok(())
    }
}
const ROOT: (u64, u64) = (1, 101);
const SERVICE: (u64, u64) = (8, 108);
const DRIVER: (u64, u64) = (7, 107);
const CUT: u64 = 2000;
fn images() -> [String; 9] {
    core::array::from_fn(|i| format!("{:02x}", i + 1).repeat(32))
}
fn hex_bytes(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn control_window(cut: u64) -> (u64, [u8; 32]) {
    let n = control::Notice {
        operation: control::Operation::ShutdownBegin,
        sequence: 1,
    };
    let mut p = control::Packet::new();
    let mut w = Memory([0; 4096]);
    p.write_request(&mut w, n, &cut.to_le_bytes()).unwrap();
    (
        u64::from_le_bytes(n.encode().unwrap()),
        Sha256::digest(w.0).into(),
    )
}
fn driver_window(cut: u64) -> (u64, [u8; 32]) {
    let n = protocol::Notice {
        operation: protocol::Operation::StopBegin,
        sequence: 1,
    };
    let mut p = protocol::Packet::new();
    let mut w = Memory([0; 4096]);
    p.write_request(&mut w, n, &cut.to_le_bytes()).unwrap();
    (
        u64::from_le_bytes(n.encode().unwrap()),
        Sha256::digest(w.0).into(),
    )
}
fn base(kind: u8, actor: usize) -> Row {
    let (process, thread) = match actor {
        0 => ROOT,
        5 => (5, 105),
        7 => DRIVER,
        8 => SERVICE,
        _ => unreachable!(),
    };
    Row {
        sequence: 0,
        kind,
        actor,
        process,
        thread,
        tick: 0,
        call: None,
        opcode: 0,
        status: 0,
        length: 0,
        value: 0,
        request: 0,
        payload: [0; 32],
        image: [actor as u8 + 1; 32],
    }
}
fn calls() -> (Call, Call) {
    (
        Call {
            epoch: 501,
            id: 200,
            endpoint: 44,
            ticket: 2,
            deadline: 900,
            caller: SERVICE,
            callee: DRIVER,
        },
        Call {
            epoch: 501,
            id: 199,
            endpoint: 45,
            ticket: 1,
            deadline: 1000,
            caller: ROOT,
            callee: SERVICE,
        },
    )
}
fn fixture(victim: usize) -> Vec<Row> {
    let (inner, outer) = calls();
    let (control, outer_hash) = control_window(CUT);
    let (driver, inner_hash) = driver_window(CUT);
    let mut watch = base(0, 0);
    watch.opcode = 3;
    watch.value = CUT;
    let mut arm = watch.clone();
    arm.opcode = if victim == 7 { 1 } else { 2 };
    let mut accepted = base(2, 0);
    accepted.call = Some(outer);
    accepted.opcode = 10;
    accepted.length = 8;
    accepted.value = CUT;
    accepted.request = control;
    accepted.payload = outer_hash;
    let mut leaf = base(4, 7);
    leaf.call = Some(inner);
    leaf.opcode = 6;
    leaf.length = 4096;
    leaf.value = outer.id;
    leaf.request = driver;
    leaf.payload = inner_hash;
    let mut parent = base(5, 8);
    parent.call = Some(outer);
    parent.opcode = 10;
    parent.length = 4096;
    parent.value = inner.id;
    parent.request = control;
    parent.payload = outer_hash;
    let mut stop = base(6, victim);
    stop.call = Some(inner);
    stop.status = 1;
    stop.value = outer.id;
    stop.request = driver;
    let mut child_return = base(7, 8);
    child_return.call = Some(inner);
    child_return.status = 5;
    child_return.request = driver;
    let mut root_return = base(7, 0);
    root_return.call = Some(outer);
    root_return.status = 5;
    root_return.request = control;
    let mut rows = vec![
        watch,
        arm,
        accepted,
        leaf,
        parent,
        stop,
        child_return,
        root_return,
        base(8, 0),
    ];
    resequence(&mut rows);
    rows
}
fn resequence(rows: &mut [Row]) {
    for (i, r) in rows.iter_mut().enumerate() {
        r.sequence = i as u64 + 1;
        r.tick = 100 + r.sequence;
    }
}
fn line_for(r: &Row, build: &str) -> String {
    let (c, cid, ep, ticket, cut, cp, ct, dp, dt) =
        r.call.map_or((0, 0, 0, 0, 0, 0, 0, 0, 0), |c| {
            (
                c.epoch, c.id, c.endpoint, c.ticket, c.deadline, c.caller.0, c.caller.1,
                c.callee.0, c.callee.1,
            )
        });
    format!(
        "EVROSION_M6_NEGATIVE protocol=1 build={build} sequence={} kind={} actor={} process={} thread={} tick={} call_epoch={c} call={cid} endpoint={ep} ticket={ticket} deadline={cut} caller_process={cp} caller_thread={ct} callee_process={dp} callee_thread={dt} opcode={} status={} length={} value={} request={} payload_sha256={} image_sha256={}\n",
        r.sequence,
        r.kind,
        r.actor,
        r.process,
        r.thread,
        r.tick,
        r.opcode,
        r.status,
        r.length,
        r.value,
        r.request,
        hex_bytes(&r.payload),
        hex_bytes(&r.image)
    )
}
fn serial(rows: &[Row]) -> Vec<u8> {
    let b = "a".repeat(64);
    let im = images();
    let mut s = format!(
        "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={b} mode=0 root_process=1 root_thread=101 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=4 block_thread=104 block_image_sha256={} system_endpoint=31 root_frames=226 block_frames=18\n",
        im[0],
        "f".repeat(64),
        im[4]
    );
    for row in rows {
        s.push_str(&line_for(row, &b));
    }
    s.into_bytes()
}
fn verified(rows: &[Row]) -> Result<Verified> {
    records(&serial(rows), &"a".repeat(64), Some(&images()))
}
fn reject(rows: &[Row], victim: usize) -> bool {
    match verified(rows) {
        Ok(v) => captured_failure(&v, victim).is_err(),
        Err(_) => true,
    }
}
fn app_denial_rows() -> Vec<Row> {
    let build = "a".repeat(64);
    let mut rows = Vec::new();
    for op in [35, 36, syscall::RPC_CALL, 53, 50, 51] {
        let mut row = base(1, 5);
        row.opcode = op;
        row.status = 1;
        row.value = match op {
            35 | 36 => 0x300,
            50 | 51 => 0x310,
            _ => 0,
        };
        row.request = match op {
            syscall::RPC_CALL => u64::from_le_bytes(*b"S\x01\x05\0\x01\0\0\0"),
            51 => 0x12345678,
            _ => 0,
        };
        row.sequence = rows.len() as u64 + 1;
        row.tick = 100 + row.sequence;
        rows.push(line(line_for(&row, &build).trim_end(), &build).unwrap());
    }
    rows
}
#[test]
fn app_denials_require_all_six_exact_shapes_including_both_byte4_memory_probes() {
    let build = "a".repeat(64);
    let rows = app_denial_rows();
    let complete = crate::network_negative::cases::app_denials;
    assert!(
        !complete(&rows[..4]).unwrap(),
        "old four probes prove no Byte4 denial"
    );
    assert!(complete(&rows).unwrap());
    for op in [50, 51] {
        let partial: Vec<_> = rows.iter().filter(|r| r.opcode != op).cloned().collect();
        assert!(!complete(&partial).unwrap());
    }
    let mut duplicate = rows.clone();
    duplicate[5] = rows[4].clone();
    assert!(complete(&duplicate).is_err());
    for mode in 0..4 {
        let mut wrong = rows[5].clone();
        match mode {
            0 => wrong.value = 0x300,
            1 => wrong.request ^= 1,
            2 => wrong.status = 0,
            _ => wrong.opcode = 52,
        }
        assert!(line(line_for(&wrong, &build).trim_end(), &build).is_err());
    }
    let mut foreign = rows.clone();
    foreign[5].thread += 1;
    assert!(complete(&foreign).is_err());
}
#[test]
fn sdk_rpc_decode_and_closed_observation_use_actual_syscall_identity() {
    use ev_kernel::{
        capability::Handle,
        user_context::{Call as Syscall, UserContext, decode},
    };

    // Encode the actual App-side request with the public service codec and SDK
    // syscall identity; the existing Core decoder is the producer boundary.
    let request = u64::from_le_bytes(
        control::Notice {
            operation: control::Operation::Connect,
            sequence: 1,
        }
        .encode()
        .unwrap(),
    );
    let mut frame = UserContext::ZERO;
    frame.registers[14] = syscall::RPC_CALL;
    frame.registers[8] = 260;
    frame.registers[9] = request;
    frame.registers[11] = 512;
    assert_eq!(
        decode(&frame),
        Ok(Syscall::Rpc {
            endpoint: Handle(260),
            value: request,
            deadline: 512,
        })
    );
    assert_ne!(syscall::RPC_CALL, syscall::CREATE_JOB);

    let mut rows = app_denial_rows();
    rows[2].opcode = frame.registers[14];
    rows[2].request = request;
    rows.push(base(8, 0));
    resequence(&mut rows);
    let bytes = serial(&rows);
    let actual = records(&bytes, &"a".repeat(64), Some(&images())).unwrap();
    assert!(crate::network_negative::cases::app_denials(actual.rows()).unwrap());

    // The old14 tag is CreateJob, never an alternative RPC observation. Every
    // other original denial remains mandatory, and a complete history matters.
    let mut stale_opcode = rows.clone();
    stale_opcode[2].opcode = syscall::CREATE_JOB;
    assert!(verified(&stale_opcode).is_err());
    for index in 0..6 {
        let mut missing = rows.clone();
        missing.remove(index);
        resequence(&mut missing);
        let actual = verified(&missing).unwrap();
        assert!(!crate::network_negative::cases::app_denials(actual.rows()).unwrap());
    }
    assert!(records(&bytes[..bytes.len() - 1], &"a".repeat(64), Some(&images())).is_err());
    let mut extra = rows.clone();
    extra.insert(6, rows[2].clone());
    resequence(&mut extra);
    let actual = verified(&extra).unwrap();
    assert!(crate::network_negative::cases::app_denials(actual.rows()).is_err());
    for mutation in 0..4 {
        let mut bad = rows.clone();
        match mutation {
            0 => bad[2].request ^= 1,
            1 => bad[2].status = 0,
            2 => bad[2].process += 1,
            _ => bad[2].sequence = bad[1].sequence,
        }
        assert!(verified(&bad).is_err());
    }
}
#[test]
fn codec_bound_nested_calls_return_only_unique_serial_bound_canonical_owners() {
    for victim in [7, 8] {
        let rows = fixture(victim);
        let bytes = serial(&rows);
        let v = verified(&rows).unwrap();
        let c = captured_failure(&v, victim).unwrap();
        assert_eq!(c.count(), 2);
        assert_eq!(c.calls(), &[calls().0, calls().1]);
        // The live remaining peer can genuinely ACK its own cancellation.
        // Only the stopped callee's owner must enter no-ACK accounting.
        let mandatory = if victim == 7 { calls().0 } else { calls().1 };
        let mut single = rows.clone();
        single.retain(|r| r.kind != 7 || r.call == Some(mandatory));
        resequence(&mut single);
        let one = captured_failure(&verified(&single).unwrap(), victim).unwrap();
        assert_eq!(one.count(), 1);
        assert_eq!(one.calls(), &[mandatory]);
        assert!(one.matches(&serial(&single)));

        assert!(c.matches(&bytes));
        let mut other = bytes.clone();
        other.extend_from_slice(b"another serial\n");
        assert!(!c.matches(&other));
        assert!(
            crate::native_protocol::record_network_negative(&other, &"a".repeat(64), &c).is_err()
        );
        assert!(
            crate::boot_protocol::check_network_negative(&other, &"a".repeat(64), Some(33), &c)
                .is_err()
        );
    }
}
#[test]
fn missing_duplicate_foreign_deadline_or_request_terminal_never_fabricates_a_reply() {
    for victim in [7, 8] {
        let original = fixture(victim);
        let mut bad = original.clone();
        bad.retain(|r| r.kind != 7);
        resequence(&mut bad);
        assert!(reject(&bad, victim));
        let mut bad = original.clone();
        bad.insert(8, bad[6].clone());
        resequence(&mut bad);
        assert!(reject(&bad, victim));
        let mut bad = original.clone();
        bad[6].call.as_mut().unwrap().id += 1;
        assert!(reject(&bad, victim));
        let mut bad = original.clone();
        bad[6].request ^= 1;
        assert!(reject(&bad, victim));
        let mut bad = original.clone();
        bad[6].tick = bad[5].tick - 1;
        assert!(reject(&bad, victim));
        let mut bad = original;
        bad[3].call.as_mut().unwrap().deadline = 1001;
        assert!(reject(&bad, victim));
    }
}
#[test]
fn each_stopped_callee_requires_its_own_peerdied_owner_even_if_other_terminal_remains() {
    for victim in [7, 8] {
        let original = fixture(victim);
        let mandatory = if victim == 7 { calls().0 } else { calls().1 };
        let mut bad = original.clone();
        bad.retain(|r| r.kind != 7 || r.call != Some(mandatory));
        resequence(&mut bad);
        assert!(
            reject(&bad, victim),
            "victim{victim} missing mandatory dead-callee owner"
        );
        for status in [4, 6] {
            let mut bad = original.clone();
            bad.iter_mut()
                .find(|r| r.kind == 7 && r.call == Some(mandatory))
                .unwrap()
                .status = status;
            assert!(
                reject(&bad, victim),
                "victim{victim} false terminal{status}"
            );
        }
    }
}
#[test]
fn foreign_root_pair_image_cut_and_replay_are_refused_before_typed_balance() {
    let original = fixture(7);
    let mut bad = original.clone();
    for r in &mut bad {
        if let Some(c) = r.call.as_mut()
            && c.caller == ROOT
        {
            c.caller = (11, 111);
        }
    }
    assert!(reject(&bad, 7));
    let mut bad = original.clone();
    bad[4].process = 18;
    bad[4].thread = 118;
    assert!(reject(&bad, 7));
    let mut bad = original.clone();
    bad[3].image = [55; 32];
    assert!(reject(&bad, 7));
    let mut bad = original.clone();
    bad[1].value += 1;
    assert!(reject(&bad, 7));
    let mut bad = original.clone();
    bad[5].tick = 900;
    for r in &mut bad[6..] {
        r.tick = 901;
    }
    assert!(reject(&bad, 7));
    let mut bad = original.clone();
    bad.insert(3, bad[2].clone());
    resequence(&mut bad);
    assert!(reject(&bad, 7));
    let mut bad = original.clone();
    bad[4].payload[0] ^= 1;
    assert!(reject(&bad, 7));
    let mut bad = original;
    bad[5].actor = 8;
    bad[5].process = 8;
    bad[5].thread = 108;
    bad[5].image = [9; 32];
    assert!(reject(&bad, 7));
}
#[test]
fn both_captured_windows_must_match_canonical_original_aggregate_not_just_each_other() {
    let original = fixture(7);
    let mut bad = original.clone();
    bad[3].payload[0] ^= 1;
    assert!(reject(&bad, 7), "arbitrary nonzero inner window");
    let mut bad = original.clone();
    let (_, wrong) = control_window(CUT - 1);
    bad[2].payload = wrong;
    bad[2].value = CUT - 1;
    bad[4].payload = wrong;
    assert!(
        reject(&bad, 7),
        "same forged outer hash and wrong aggregate"
    );
    let mut bad = original;
    bad[2].request ^= 1 << 8;
    bad[4].request = bad[2].request;
    bad[7].request = bad[2].request;
    assert!(reject(&bad, 7), "noncanonical outer notice version");
}
#[test]
fn missing_summary_omission_truncation_unknown_shape_and_after_summary_rows_fail_closed() {
    let original = fixture(7);
    let build = "a".repeat(64);
    let mut bad = original.clone();
    bad.pop();
    assert!(records(&serial(&bad), &build, Some(&images())).is_err());
    let mut bad = original.clone();
    bad.last_mut().unwrap().value = 1;
    assert!(records(&serial(&bad), &build, Some(&images())).is_err());
    let mut bytes = serial(&original);
    bytes.pop();
    assert!(records(&bytes, &build, Some(&images())).is_err());
    let mut bad = original.clone();
    bad.push(bad[6].clone());
    resequence(&mut bad);
    assert!(records(&serial(&bad), &build, Some(&images())).is_err());
    let text = String::from_utf8(serial(&original)).unwrap();
    for bad in [
        text.replace("sequence=1 ", "sequence=01 "),
        text.replace("kind=4 ", "kind=9 "),
        text.replace("tick=104 ", "tick=104 extra=1 "),
        text.replace(
            &format!("build={build}"),
            &format!("build={}", "b".repeat(64)),
        ),
    ] {
        assert!(records(bad.as_bytes(), &build, Some(&images())).is_err());
    }
}
