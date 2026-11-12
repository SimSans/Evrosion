use std::process::Command;
pub fn preview(options: &crate::cli::BootOptions) -> Result<(), String> {
    crate::native_workflow::preview(options)
}
pub fn run(workflow: &str) -> Result<(), String> {
    if workflow == "ipc-bench" {
        return crate::ipc_bench_workflow::run();
    }
    if workflow == "native-system" {
        return crate::native3_workflow::run_system();
    }
    if workflow == "native-owner-grants" {
        return crate::native3_workflow::run_grants();
    }
    if workflow == "provider-switch" {
        return crate::provider_workflow::run();
    }
    if workflow == "native-platform" {
        return crate::native_workflow::run();
    }
    if workflow == "storage-recovery" {
        return crate::owner_workflow::run();
    }
    if workflow == "storage-progress" {
        return crate::generation::run_progress();
    }
    if workflow == "storage-file" {
        return crate::file_workflow::run();
    }
    if workflow == "storage-pio" {
        return crate::storage::run();
    }
    if workflow == "storage-journal" {
        return crate::journal::run();
    }
    if workflow == "storage-generation" {
        return crate::generation::run();
    }
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?;
    let status = Command::new("python3")
        .arg(root.join("tools/m0/acceptance.py"))
        .arg(workflow)
        .env(
            "EV_FRONTEND",
            std::env::current_exe().map_err(|e| e.to_string())?,
        )
        .current_dir(root)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{workflow} exited {status}; see the evidence printed above"
        ))
    }
}
pub fn recover(source: &std::path::Path) -> Result<(), String> {
    crate::owner_workflow::resume(source)
}
