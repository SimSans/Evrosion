//! Explicit private Linux/x86-64 BOOTTIME interposition. This qualifies the
//! owned elapsed-source launch, not UTC, host attestation or a guest RTC adapter.
use crate::{
    build::{self, Result},
    storage,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const SOURCE: &[u8] = include_bytes!("../../m6/clock_boottime.c");
const AUDIT_LIMIT: usize = 32 * 48;
const CALLSITE: u64 = 0xba8f6e;

#[derive(Clone, Serialize)]
struct Identity {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    dev: u64,
    inode: u64,
}
impl Identity {
    fn read(path: &Path, maximum: u64) -> Result<Self> {
        let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.is_file()
            || m.file_type().is_symlink()
            || m.len() == 0
            || m.len() > maximum
            || m.nlink() != 1
        {
            return Err("clock input is not its bounded regular file".into());
        }
        Ok(Self {
            path: path.canonicalize().map_err(|e| e.to_string())?,
            sha256: build::hash_file(path)?,
            bytes: m.len(),
            dev: m.dev(),
            inode: m.ino(),
        })
    }
    fn unchanged(&self) -> Result<()> {
        let current = Self::read(&self.path, self.bytes)?;
        if current.sha256 != self.sha256
            || current.bytes != self.bytes
            || current.dev != self.dev
            || current.inode != self.inode
        {
            return Err("clock input identity changed".into());
        }
        Ok(())
    }
}
pub(crate) struct Prepared {
    directory: PathBuf,
    primary: Identity,
    source: Identity,
    module: Identity,
    compiler: Identity,
    executable: Identity,
    audit: PathBuf,
    loaded: bool,
}
fn forbidden_environment(key: &OsStr) -> bool {
    key.as_bytes().starts_with(b"LD_")
        || matches!(
            key.to_str(),
            Some(
                "GLIBC_TUNABLES"
                    | "QEMU_PLUGIN"
                    | "EVROSION_CLOCK_AUDIT_PATH"
                    | "EVROSION_CLOCK_AUDIT_FD"
            )
        )
}
fn clear_loader(command: &mut Command) {
    let keys: BTreeSet<_> = std::env::vars_os()
        .map(|(k, _)| k)
        .chain(command.get_envs().map(|(k, _)| k.to_owned()))
        .filter(|k| forbidden_environment(k))
        .collect();
    for key in keys {
        command.env_remove(key);
    }
}
fn preload_path(path: &Path) -> Result<&str> {
    let s = path.to_str().ok_or("clock module path is not UTF8")?;
    if !path.is_absolute() || s.bytes().any(|b| b.is_ascii_whitespace() || b == b':') {
        return Err("clock module path cannot use LD_PRELOAD whitespace/colon grammar".into());
    }
    Ok(s)
}
fn compiler() -> Result<PathBuf> {
    for directory in
        std::env::split_paths(&std::env::var_os("PATH").ok_or("clock compiler PATH absent")?)
    {
        let path = directory.join("cc");
        if fs::metadata(&path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
            return path.canonicalize().map_err(|e| e.to_string());
        }
    }
    Err("C compiler required for explicit VM clock profile".into())
}
pub(crate) fn prepare(root: &Path, run: &Path, executable: &Path) -> Result<Prepared> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let run = run.canonicalize().map_err(|e| e.to_string())?;
    let relative = run
        .strip_prefix(&root)
        .map_err(|_| "clock evidence escaped root")?;
    storage::directory_beneath(&root, relative)?;
    let directory = run.join("elapsed-clock");
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let primary = root.join("tools/m6/clock_boottime.c");
    let primary = Identity::read(&primary, 65536)?;
    if primary.bytes != SOURCE.len() as u64
        || primary.sha256 != format!("{:x}", Sha256::digest(SOURCE))
    {
        return Err("clock source differs from compiled frontend primary source".into());
    }
    let source_path = directory.join("clock_boottime.c");
    storage::immutable_new(&source_path, SOURCE)?;
    let module_path = directory.join("libevrosion-clock.so");
    preload_path(&module_path)?;
    let compiler = Identity::read(&compiler()?, 128 * 1024 * 1024)?;
    let arguments = vec![
        "-std=c11".into(),
        "-O2".into(),
        "-fPIC".into(),
        "-shared".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-fvisibility=hidden".into(),
        "-Wl,-z,relro,-z,now".into(),
        "-o".into(),
        module_path.to_string_lossy().into_owned(),
        source_path.to_string_lossy().into_owned(),
    ];
    let log_path = directory.join("compiler.log");
    let log = File::create(&log_path).map_err(|e| e.to_string())?;
    let mut command = Command::new(&compiler.path);
    command
        .args(&arguments)
        .current_dir(&directory)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log);
    clear_loader(&mut command);
    for key in [
        "GCC_EXEC_PREFIX",
        "COMPILER_PATH",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "LD_RUN_PATH",
    ] {
        command.env_remove(key);
    }
    let status = crate::boot::supervised(&mut command, &[&log_path], Duration::from_secs(30));
    storage::json_new(
        &directory.join("compiler-command.json"),
        &json!({"program":compiler,"arguments":arguments,"exit":status.as_ref().ok().and_then(|s|s.code()),"error":status.as_ref().err(),"log_sha256":build::hash_file(&log_path)?}),
    )?;
    if !status?.success() {
        return Err("clock module compilation failed".into());
    }
    fs::set_permissions(&module_path, fs::Permissions::from_mode(0o500))
        .map_err(|e| e.to_string())?;
    let prepared = Prepared {
        directory: directory.clone(),
        primary,
        source: Identity::read(&source_path, 65536)?,
        module: Identity::read(&module_path, 1024 * 1024)?,
        compiler,
        executable: Identity::read(executable, 128 * 1024 * 1024)?,
        audit: directory.join("clock.audit"),
        loaded: false,
    };
    storage::json_new(
        &directory.join("prepared.json"),
        &json!({"schema":1,"kind":"owned-explicit-boottime-module","primary":prepared.primary,"source":prepared.source,"module":prepared.module,"compiler":prepared.compiler,"qemu":prepared.executable,"audit_path":prepared.audit,"rtc":crate::vm_profile::RTC,"utc_provider_qualified":false,"scope":"Trusted owner host/compiler/loader; explicit module only. Prelaunch maps/imported caller and guest qualification still required"}),
    )?;
    Ok(prepared)
}
#[derive(Debug, Serialize)]
struct Record {
    requested: i32,
    actual: i32,
    seconds: i64,
    nanoseconds: i64,
    caller: u64,
    sequence: u64,
}
fn records(bytes: &[u8]) -> Result<Vec<Record>> {
    if bytes.is_empty() || bytes.len() > AUDIT_LIMIT || !bytes.len().is_multiple_of(48) {
        return Err("clock audit extent incomplete/empty/excessive".into());
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for b in bytes.as_chunks::<48>().0 {
        if &b[..8] != b"EVCLKB02" {
            return Err("clock audit magic".into());
        }
        let r = Record {
            requested: i32::from_le_bytes(b[8..12].try_into().unwrap()),
            actual: i32::from_le_bytes(b[12..16].try_into().unwrap()),
            seconds: i64::from_le_bytes(b[16..24].try_into().unwrap()),
            nanoseconds: i64::from_le_bytes(b[24..32].try_into().unwrap()),
            caller: u64::from_le_bytes(b[32..40].try_into().unwrap()),
            sequence: u64::from_le_bytes(b[40..48].try_into().unwrap()),
        };
        if !(0..1_000_000_000).contains(&r.nanoseconds)
            || !(1..=32).contains(&r.sequence)
            || !seen.insert(r.sequence)
            || (r.requested == 1 && r.actual != 7)
            || (r.actual == 7 && r.seconds < 0)
            || (r.requested != 1 && r.actual != r.requested)
            || (r.caller == 0 && (r.requested != 7 || r.actual != 7))
        {
            return Err("clock audit values/replay/source mismatch".into());
        }
        out.push(r);
    }
    if seen.iter().copied().ne(1..=out.len() as u64)
        || out.iter().filter(|r| r.caller == 0).count() != 1
    {
        return Err("clock constructor or record sequence missing".into());
    }
    Ok(out)
}
#[derive(Debug)]
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    permissions: String,
    major: u64,
    minor: u64,
    inode: u64,
    path: String,
}
fn mappings(text: &str) -> Result<Vec<Mapping>> {
    if text.len() > 1024 * 1024 {
        return Err("clock maps bound".into());
    }
    text.lines()
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return Err("clock maps shape".into());
            }
            let (start, end) = fields[0].split_once('-').ok_or("clock maps address")?;
            let (major, minor) = fields[3].split_once(':').ok_or("clock maps device")?;
            let hex =
                |s: &str| u64::from_str_radix(s, 16).map_err(|_| "clock maps number".to_string());
            let m = Mapping {
                start: hex(start)?,
                end: hex(end)?,
                offset: hex(fields[2])?,
                permissions: fields[1].into(),
                major: hex(major)?,
                minor: hex(minor)?,
                inode: fields[4].parse().map_err(|_| "clock maps inode")?,
                path: fields.get(5..).unwrap_or_default().join(" "),
            };
            if m.start >= m.end || m.permissions.len() != 4 {
                return Err("clock maps extent".into());
            }
            Ok(m)
        })
        .collect()
}
fn matches_identity(m: &Mapping, i: &Identity) -> bool {
    let major = ((i.dev >> 8) & 0xfff) | ((i.dev >> 32) & 0xfffff000);
    let minor = (i.dev & 0xff) | ((i.dev >> 12) & 0xffffff00);
    m.major == major && m.minor == minor && m.inode == i.inode && Path::new(&m.path) == i.path
}
fn loaded_proof(
    maps: &[Mapping],
    audit: &[Record],
    module: &Identity,
    executable: &Identity,
) -> Result<u64> {
    let module_maps: Vec<_> = maps
        .iter()
        .filter(|m| matches_identity(m, module))
        .collect();
    if module_maps.is_empty()
        || !module_maps
            .iter()
            .any(|m| m.permissions.as_bytes()[2] == b'x')
        || module_maps
            .iter()
            .any(|m| &m.permissions.as_bytes()[1..3] == b"wx")
    {
        return Err("owned clock module is not the actual executable mapping".into());
    }
    let base = maps
        .iter()
        .find(|m| matches_identity(m, executable) && m.offset == 0)
        .ok_or("actual QEMU image base missing")?
        .start;
    let caller = base.checked_add(CALLSITE).ok_or("clock caller overflow")?;
    if !maps.iter().any(|m| {
        matches_identity(m, executable)
            && m.permissions.as_bytes()[2] == b'x'
            && m.start <= caller
            && caller < m.end
    }) || !audit
        .iter()
        .any(|r| r.requested == 1 && r.actual == 7 && r.caller == caller)
    {
        return Err("actual reviewed QEMU imported BOOTTIME callsite missing".into());
    }
    Ok(caller)
}
impl Prepared {
    pub(crate) fn apply(&self, command: &mut Command) -> Result<()> {
        self.primary.unchanged()?;
        self.source.unchanged()?;
        self.module.unchanged()?;
        self.compiler.unchanged()?;
        self.executable.unchanged()?;
        if fs::symlink_metadata(&self.audit).is_ok() {
            return Err("clock audit path must be new".into());
        }
        clear_loader(command);
        command
            .env("LD_PRELOAD", preload_path(&self.module.path)?)
            .env("EVROSION_CLOCK_AUDIT_PATH", &self.audit);
        let delta:Vec<_> = command.get_envs().filter(|(key,_)| forbidden_environment(key)).map(|(key,value)| json!({"key":key.to_string_lossy(),"value":value.map(|s|s.to_string_lossy())})).collect();
        storage::json_new(
            &self.directory.join("loader-environment.json"),
            &json!({"overrides":delta,"scope":"Removed values are not retained; exactly this owned LD_PRELOAD/audit path is supplied to this child only"}),
        )?;
        Ok(())
    }
    fn audit(&self) -> Result<Vec<Record>> {
        let m = fs::symlink_metadata(&self.audit).map_err(|e| e.to_string())?;
        let owner = fs::metadata(&self.directory)
            .map_err(|e| e.to_string())?
            .uid();
        if !m.is_file()
            || m.file_type().is_symlink()
            || m.nlink() != 1
            || m.uid() != owner
            || m.mode() & 0o777 != 0o600
            || m.len() > AUDIT_LIMIT as u64
        {
            return Err("clock audit ownership/mode/extent".into());
        }
        let mut bytes = Vec::new();
        File::open(&self.audit)
            .map_err(|e| e.to_string())?
            .take(AUDIT_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        records(&bytes)
    }
    pub(crate) fn verify_and_start(&mut self, child: &mut Child, run: &Path) -> Result<()> {
        self.verify_start(child, run, false)
    }
    /// Same loaded-clock checks and fixed launch arguments; only this explicit
    /// cold acquisition test disconnects the owned reference NIC before cont.
    pub(crate) fn verify_and_start_acquisition_cold(
        &mut self,
        child: &mut Child,
        run: &Path,
    ) -> Result<()> {
        self.verify_start(child, run, true)
    }
    fn verify_start(
        &mut self,
        child: &mut Child,
        run: &Path,
        acquisition_cold: bool,
    ) -> Result<()> {
        if self.loaded {
            return Err("clock prelaunch verification replay".into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last = "clock constructor/audit not yet available".to_string();
        loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!(
                    "clock-protected QEMU exited {status} before prelaunch verification"
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!("clock prelaunch verification deadline: {last}"));
            }
            let maps_path = PathBuf::from(format!("/proc/{}/maps", child.id()));
            let attempt = (|| {
                let text = fs::read_to_string(&maps_path).map_err(|e| e.to_string())?;
                let maps = mappings(&text)?;
                let audit = self.audit()?;
                let caller = loaded_proof(&maps, &audit, &self.module, &self.executable)?;
                self.primary.unchanged()?;
                self.module.unchanged()?;
                self.source.unchanged()?;
                self.executable.unchanged()?;
                let qmp = run.join("qmp.sock");
                if !qmp.exists() {
                    return Err("clock QMP not yet available".into());
                }
                Ok((text, audit, caller))
            })();
            match attempt {
                Ok((maps, audit, caller)) => {
                    storage::immutable_new(
                        &self.directory.join("loaded-maps.txt"),
                        maps.as_bytes(),
                    )?;
                    storage::json_new(
                        &self.directory.join("loaded.json"),
                        &json!({"schema":1,"pid":child.id(),"module":self.module,"qemu":self.executable,"reviewed_import_caller":caller,"records":audit,"utc_provider_qualified":false}),
                    )?;
                    let mut qmp = crate::qmp::Qmp::connect(run, deadline)?;
                    let result = if acquisition_cold {
                        qmp.start_acquisition_cold_prelaunch()
                    } else {
                        qmp.start_verified_prelaunch()
                    };
                    storage::json_new(
                        &self.directory.join("prelaunch-qmp.json"),
                        &json!({"transcript":qmp.transcript(),"error":result.as_ref().err(),"acquisition_cold_link_down":acquisition_cold,"scope":"Owned reference NIC test isolation; no physical-offline or UTC qualification claim."}),
                    )?;
                    result?;
                    self.loaded = true;
                    return Ok(());
                }
                Err(e) => last = e,
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    pub(crate) fn postflight(&self) -> Result<()> {
        let checked = (|| {
            self.primary.unchanged()?;
            self.source.unchanged()?;
            self.module.unchanged()?;
            self.compiler.unchanged()?;
            self.executable.unchanged()?;
            let records = self.audit()?;
            if !self.loaded {
                return Err("clock prelaunch release was never verified".into());
            }
            Ok(records)
        })();
        let audit_identity = Identity::read(&self.audit, AUDIT_LIMIT as u64).ok();
        storage::json_new(
            &self.directory.join("postflight.json"),
            &json!({"schema":1,"loaded_before_release":self.loaded,"inputs_unchanged":checked.is_ok(),"records":checked.as_ref().ok(),"audit":audit_identity,"error":checked.as_ref().err(),"utc_provider_qualified":false}),
        )?;
        checked.map(|_| ())
    }
}

#[cfg(test)]
mod tests;
