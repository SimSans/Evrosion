use ev::cli::{self, Cli};
use ev::doctor::{self, Host};
use ev::process::SystemRunner;
use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(Cli::Help) => print!("{}", cli::HELP),
        Ok(Cli::DoctorHelp) => print!("{}", cli::DOCTOR_HELP),
        Ok(Cli::Version) => println!(
            "ev {} (Internal Developer Preview)",
            env!("CARGO_PKG_VERSION")
        ),
        Ok(Cli::Build(options)) => return outcome(ev::build::build(&options)),
        Ok(Cli::Boot(options)) => return outcome(ev::boot::boot(&options)),
        Ok(Cli::Preview(options)) => return outcome(ev::workflow::preview(&options)),
        Ok(Cli::Workflow(workflow)) if workflow == "desktop-graph" => {
            return outcome(ev::desktop_workflow::run());
        }
        Ok(Cli::Workflow(workflow)) if workflow == "display-surface" => {
            return outcome(ev::graphics_workflow::run());
        }
        Ok(Cli::Workflow(workflow)) => return outcome(ev::workflow::run(&workflow)),
        Ok(Cli::Workspace(args)) => return outcome(ev::workspace::execute(&args)),
        Ok(Cli::App(args)) => return outcome(ev::workspace::execute_app(&args)),
        Ok(Cli::Recover(source)) => return outcome(ev::workflow::recover(&source)),
        Ok(Cli::OwnerUiExercise(options)) => {
            return outcome(ev::workflow::owner_ui_exercise(&options));
        }
        Ok(Cli::OwnerUiFirstUse(options)) => {
            return outcome(ev::workflow::owner_ui_first_use(&options));
        }
        Ok(Cli::OwnerUi(options)) => return outcome(ev::workflow::owner_ui(&options)),
        Ok(Cli::Acquisition(options)) => return outcome(ev::workflow::acquisition(&options)),
        Ok(Cli::SystemHealth(options)) => return outcome(ev::workflow::system_health(&options)),
        Ok(Cli::DocumentUpdate(options)) => {
            return outcome(ev::workflow::document_update(&options));
        }
        Ok(Cli::Doctor(options)) => {
            let current = match std::env::current_dir() {
                Ok(current) => current,
                Err(error) => {
                    eprintln!("Cannot determine the working directory: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let report =
                doctor::inspect(&options, &Host::detect(&current), &SystemRunner, &current);
            print!("{}", report.render());
            return if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn outcome(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL {error}");
            ExitCode::FAILURE
        }
    }
}
