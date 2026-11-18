use std::process::Command;
pub fn owner_ui_exercise(options: &crate::cli::AcquisitionOptions) -> Result<(), String> {
    crate::owner_ui_workflow::exercise(options)
}
pub fn owner_ui_first_use(options: &crate::cli::AcquisitionOptions) -> Result<(), String> {
    crate::owner_ui_workflow::first_use(options)
}
pub fn owner_ui(options: &crate::cli::AcquisitionOptions) -> Result<(), String> {
    crate::owner_ui_workflow::run(options)
}
pub fn acquisition(options: &crate::cli::AcquisitionOptions) -> Result<(), String> {
    crate::acquisition::run(options)
}
pub fn preview(options: &crate::cli::BootOptions) -> Result<(), String> {
    crate::native_workflow::preview(options)
}
pub fn run(workflow: &str) -> Result<(), String> {
    for goal in [
        crate::network_negative_contract::Goal::AppDenial,
        crate::network_negative_contract::Goal::Destination,
        crate::network_negative_contract::Goal::DriverStop,
        crate::network_negative_contract::Goal::ServiceStop,
        crate::network_negative_contract::Goal::LinkLoss,
        crate::network_negative_contract::Goal::Endurance,
    ] {
        if workflow == goal.name() {
            return crate::network_negative::run(goal);
        }
    }
    if workflow == "update-namespace-probe" {
        return crate::network::probe(crate::network_io::Goal::UpdateNamespace);
    }
    if workflow == "network-probe" {
        return crate::network::probe(crate::network_io::Goal::Hello);
    }
    if workflow == "time-probe" {
        return crate::network::probe(crate::network_io::Goal::Time);
    }
    if workflow == "time-pause-probe" {
        return crate::network::probe(crate::network_io::Goal::TimePause);
    }
    if workflow == "time-refresh-probe" {
        return crate::network::probe(crate::network_io::Goal::TimeRefresh);
    }
    if workflow == "time-corrupt-probe" {
        return crate::network::probe(crate::network_io::Goal::TimeCorrupt);
    }
    if workflow == "entropy-missing-probe" {
        return crate::network::probe(crate::network_io::Goal::MissingEntropy);
    }
    if workflow == "network-session" {
        return crate::network::run();
    }
    if workflow == "document-workflow" {
        return crate::document_workflow::run();
    }
    if workflow == "document-compatibility" {
        return crate::document_compatibility::run();
    }
    if workflow == "document-session" || workflow == "document-session-guide" {
        return crate::document_session::run(workflow == "document-session-guide");
    }
    if workflow == "session" || workflow == "session-conformance" {
        return crate::session::run(workflow == "session-conformance");
    }
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

pub fn system_health(options: &crate::cli::AcquisitionOptions) -> Result<(), String> {
    crate::system_health::run(options)
}
pub fn document_update(options: &crate::cli::AcquisitionOptions) -> Result<(), String> {
    crate::document_update::run(options)
}
