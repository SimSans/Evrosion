use super::*;
use std::os::unix::fs::symlink;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../build/test-tmp")
            .join(format!(
                "clock-host-tests-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir(&path).unwrap();
        let path = path.canonicalize().unwrap();
        fs::create_dir_all(path.join("tools/m6")).unwrap();
        fs::write(path.join("tools/m6/clock_boottime.c"), SOURCE).unwrap();
        fs::create_dir(path.join("run")).unwrap();
        Self(path)
    }
    fn prepare(&self) -> Prepared {
        prepare(
            &self.0,
            &self.0.join("run"),
            &Path::new("/bin/true").canonicalize().unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn encode(requested: i32, actual: i32, caller: u64, sequence: u64) -> [u8; 48] {
    let mut b = [0; 48];
    b[..8].copy_from_slice(b"EVCLKB02");
    b[8..12].copy_from_slice(&requested.to_le_bytes());
    b[12..16].copy_from_slice(&actual.to_le_bytes());
    b[16..24].copy_from_slice(&123i64.to_le_bytes());
    b[24..32].copy_from_slice(&456i64.to_le_bytes());
    b[32..40].copy_from_slice(&caller.to_le_bytes());
    b[40..].copy_from_slice(&sequence.to_le_bytes());
    b
}
#[test]
fn audit_rejects_empty_truncation_replay_missing_constructor_or_clock_fallback() {
    let mut bytes = encode(7, 7, 0, 1).to_vec();
    bytes.extend_from_slice(&encode(1, 7, 0x1234, 2));
    assert_eq!(records(&bytes).unwrap().len(), 2);
    for len in [0, 1, 47, 49, 95] {
        assert!(records(&bytes[..len]).is_err());
    }
    for row in [
        encode(1, 1, 0x1234, 2),
        encode(1, 7, 0x1234, 1),
        encode(7, 7, 0, 2),
        encode(1, 7, 0x1234, 33),
    ] {
        let mut malformed = encode(7, 7, 0, 1).to_vec();
        malformed.extend_from_slice(&row);
        assert!(records(&malformed).is_err());
    }
    assert!(records(&encode(1, 7, 0x1234, 1)).is_err());
    let mut huge = Vec::new();
    for n in 1..=33 {
        huge.extend_from_slice(&encode(1, 7, n, n));
    }
    assert!(records(&huge).is_err());
    let mut invalid = bytes;
    invalid[24..32].copy_from_slice(&1_000_000_000i64.to_le_bytes());
    assert!(records(&invalid).is_err());
}
#[test]
fn loaded_proof_requires_exact_file_identity_executable_map_and_imported_caller() {
    let identity = |path: &str, inode| Identity {
        path: path.into(),
        sha256: "x".into(),
        bytes: 1,
        dev: 0,
        inode,
    };
    let module = identity("/owned/module.so", 1);
    let qemu = identity("/owned/qemu", 2);
    let base = 0x10000000;
    let caller = base + CALLSITE;
    let text = format!(
        "{base:x}-10001000 r--p 00000000 00:00 2 /owned/qemu\n10001000-11000000 r-xp 00001000 00:00 2 /owned/qemu\n20000000-20001000 r-xp 00000000 00:00 1 /owned/module.so\n"
    );
    let maps = mappings(&text).unwrap();
    let mut bytes = encode(7, 7, 0, 1).to_vec();
    bytes.extend_from_slice(&encode(1, 7, caller, 2));
    let audit = records(&bytes).unwrap();
    assert_eq!(loaded_proof(&maps, &audit, &module, &qemu).unwrap(), caller);
    assert!(loaded_proof(&maps, &audit, &identity("/owned/module.so", 3), &qemu).is_err());
    assert!(
        loaded_proof(
            &mappings(&text.replace("r-xp 00000000", "rwxp 00000000")).unwrap(),
            &audit,
            &module,
            &qemu
        )
        .is_err()
    );
    assert!(
        loaded_proof(
            &maps,
            &records(&encode(7, 7, 0, 1)).unwrap(),
            &module,
            &qemu
        )
        .is_err()
    );
    let mut wrong = encode(7, 7, 0, 1).to_vec();
    wrong.extend_from_slice(&encode(1, 7, caller + 1, 2));
    assert!(loaded_proof(&maps, &records(&wrong).unwrap(), &module, &qemu).is_err());
}
#[test]
fn loader_grammar_and_every_loader_override_are_closed_without_global_env_mutation() {
    for path in [
        "relative.so",
        "/owned/space path.so",
        "/owned/a:b.so",
        "/owned/a\tb.so",
    ] {
        assert!(preload_path(Path::new(path)).is_err());
    }
    assert!(preload_path(Path::new("/owned/module.so")).is_ok());
    let mut command = Command::new("/bin/true");
    for key in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_ANY_FUTURE",
        "GLIBC_TUNABLES",
        "QEMU_PLUGIN",
        "EVROSION_CLOCK_AUDIT_FD",
    ] {
        command.env(key, "unqualified");
    }
    clear_loader(&mut command);
    assert!(
        command
            .get_envs()
            .filter(|(key, _)| forbidden_environment(key))
            .all(|(_, value)| value.is_none())
    );
}
#[test]
fn exact_primary_module_constructor_creates_new_owned_audit_without_utc_claim() {
    let f = Fixture::new();
    let p = f.prepare();
    let mut command = Command::new("/bin/true");
    p.apply(&mut command).unwrap();
    assert!(command.status().unwrap().success());
    let rows = p.audit().unwrap();
    assert!(
        rows.iter()
            .any(|r| r.requested == 7 && r.actual == 7 && r.caller == 0)
    );
    assert_eq!(fs::metadata(&p.audit).unwrap().mode() & 0o777, 0o600);
    assert!(p.apply(&mut Command::new("/bin/true")).is_err());
    assert!(p.postflight().is_err()); // Constructor alone cannot release/prove a guest.
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(p.directory.join("prepared.json")).unwrap()).unwrap();
    assert_eq!(receipt["utc_provider_qualified"], false);
}
#[test]
fn actual_constructor_refuses_existing_and_symbolic_audit_paths_with_125() {
    for symbolic in [false, true] {
        let f = Fixture::new();
        let p = f.prepare();
        let target = p.directory.join("foreign");
        fs::write(&target, b"unchanged").unwrap();
        if symbolic {
            symlink(&target, &p.audit).unwrap();
        } else {
            fs::write(&p.audit, b"unchanged").unwrap();
        }
        let mut command = Command::new("/bin/true");
        clear_loader(&mut command);
        command
            .env("LD_PRELOAD", &p.module.path)
            .env("EVROSION_CLOCK_AUDIT_PATH", &p.audit);
        assert_eq!(command.status().unwrap().code(), Some(125));
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        if !symbolic {
            assert_eq!(fs::read(&p.audit).unwrap(), b"unchanged");
        }
    }
}
#[test]
fn source_or_module_change_refuses_before_any_qemu_spawn() {
    for primary in [true, false] {
        let f = Fixture::new();
        let p = f.prepare();
        let path = if primary {
            f.0.join("tools/m6/clock_boottime.c")
        } else {
            p.module.path.clone()
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"different").unwrap();
        assert!(p.apply(&mut Command::new("/bin/true")).is_err());
        assert!(!p.audit.exists());
    }
}
#[test]
fn actual_source_failure_before_constructor_or_during_use_exits125_without_fallback() {
    const PROBE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
static int deny(void) {
    struct sock_filter f[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clock_gettime,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,CLOCK_BOOTTIME,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog p={sizeof(f)/sizeof(f[0]),f};
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
}

int main(int argc,char **argv) {
    if(argc!=3)return 101;
    if(argv[2][0]=='b'&&deny())return 102;
    void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!module)return 103;
    if(argv[2][0]!='b'&&deny())return 104;
    int (*read_clock)(clockid_t,struct timespec *)=dlsym(module,"clock_gettime");if(!read_clock)return 105;
    struct timespec value;return read_clock(CLOCK_MONOTONIC,&value)==0?0:106;
}
"#;
    for mode in ["before", "after"] {
        let f = Fixture::new();
        let p = f.prepare();
        let source = p.directory.join("failure-probe.c");
        let program = p.directory.join("failure-probe");
        fs::write(&source, PROBE).unwrap();
        let mut compile = Command::new(&p.compiler.path);
        clear_loader(&mut compile);
        assert!(
            compile
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .args(["-ldl", "-o"])
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let mut command = Command::new(&program);
        clear_loader(&mut command);
        command
            .arg(&p.module.path)
            .arg(mode)
            .env("EVROSION_CLOCK_AUDIT_PATH", &p.audit);
        assert_eq!(command.status().unwrap().code(), Some(125));
        if mode == "before" {
            assert!(!p.audit.exists());
        } else {
            assert_eq!(p.audit().unwrap().len(), 1);
        }
    }
}

#[test]
fn repeated_library_clock_reads_leave_a_witness_for_later_distinct_calls() {
    const PROBE: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <time.h>
static volatile long observed;
__attribute__((noinline)) static int early(void) {
    struct timespec value;
    if(clock_gettime(CLOCK_MONOTONIC,&value))return 1;
    observed=value.tv_nsec;return 0;
}
__attribute__((noinline)) static int later(clockid_t requested) {
    struct timespec value;
    if(clock_gettime(requested,&value))return 2;
    observed=value.tv_nsec;return 0;
}
int main(void) {
    for(unsigned i=0;i<10000;++i)if(early())return 3;
    return later(CLOCK_MONOTONIC)||later(CLOCK_REALTIME);
}
"#;
    let f = Fixture::new();
    let p = f.prepare();
    let source = p.directory.join("repeat-probe.c");
    let program = p.directory.join("repeat-probe");
    fs::write(&source, PROBE).unwrap();
    let mut compile = Command::new(&p.compiler.path);
    clear_loader(&mut compile);
    assert!(
        compile
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .unwrap()
            .success()
    );
    let mut command = Command::new(&program);
    p.apply(&mut command).unwrap();
    assert!(command.status().unwrap().success());
    let audit = p.audit().unwrap();
    assert_eq!(audit.len(), 4);
    assert_eq!(
        audit
            .iter()
            .filter(|r| r.requested == 1 && r.actual == 7)
            .count(),
        2
    );
    assert_eq!(
        audit
            .iter()
            .filter(|r| r.requested == 0 && r.actual == 0)
            .count(),
        1
    );
    assert!(p.postflight().is_err()); // Distinct library calls are still no QEMU proof.
}
