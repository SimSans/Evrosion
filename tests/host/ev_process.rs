#![cfg(unix)]

mod support;

use ev::process::{CAPTURE_LIMIT, Invocation, ProcessError, Runner, SystemRunner};
use std::ffi::OsString;
use std::io::ErrorKind;
use support::TempDirectory;

#[test]
fn arguments_are_not_interpreted_as_shell_code() {
    let directory = TempDirectory::new();
    let payload = "spaces 'quotes' \"double quotes\" $(touch unexpected-file); * $HOME";
    let invocation = Invocation::new("/usr/bin/printf", &["%s\n", payload], &directory.0);
    let output = SystemRunner.run(&invocation).unwrap().checked().unwrap();
    assert_eq!(output.stdout, format!("{payload}\n").as_bytes());
    assert!(!directory.0.join("unexpected-file").exists());
}

#[test]
fn process_status_and_both_streams_survive_failure() {
    let directory = TempDirectory::new();
    let invocation = Invocation::new(
        "/usr/bin/python3",
        &[
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr); sys.exit(23)",
        ],
        &directory.0,
    );
    let error = SystemRunner
        .run(&invocation)
        .unwrap()
        .checked()
        .unwrap_err();
    match error {
        ProcessError::Exit(output) => {
            assert_eq!(output.status.code(), Some(23));
            assert_eq!(output.stdout, b"out\n");
            assert_eq!(output.stderr, b"err\n");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[test]
fn missing_executable_has_a_structured_spawn_error() {
    let directory = TempDirectory::new();
    let invocation = Invocation::new(
        directory.0.join("missing"),
        &[] as &[OsString],
        &directory.0,
    );
    match SystemRunner.run(&invocation).unwrap_err() {
        ProcessError::Spawn { source, .. } => assert_eq!(source.kind(), ErrorKind::NotFound),
        other => panic!("wrong error: {other}"),
    }
}

#[test]
fn large_simultaneous_streams_do_not_deadlock() {
    let directory = TempDirectory::new();
    let invocation = Invocation::new(
        "/usr/bin/python3",
        &[
            "-c",
            "import sys; sys.stdout.write('a' * 262144); sys.stderr.write('b' * 262144)",
        ],
        &directory.0,
    );
    let output = SystemRunner.run(&invocation).unwrap().checked().unwrap();
    assert_eq!(output.stdout.len(), 262144);
    assert_eq!(output.stderr.len(), 262144);
}

#[test]
fn probe_output_is_bounded() {
    let directory = TempDirectory::new();
    let code = format!("import sys; sys.stdout.write('a' * {})", CAPTURE_LIMIT + 1);
    let invocation = Invocation::new("/usr/bin/python3", &["-c", &code], &directory.0);
    assert!(matches!(
        SystemRunner.run(&invocation),
        Err(ProcessError::OutputLimit("stdout"))
    ));
}

#[test]
fn probes_disable_automatic_installs_network_and_git_refresh_writes() {
    let directory = TempDirectory::new();
    let invocation = Invocation::new(
        "/usr/bin/printenv",
        &[
            "RUSTUP_AUTO_INSTALL",
            "CARGO_NET_OFFLINE",
            "GIT_OPTIONAL_LOCKS",
            "PYTHONDONTWRITEBYTECODE",
        ],
        &directory.0,
    );
    let output = SystemRunner.run(&invocation).unwrap().checked().unwrap();
    assert_eq!(output.stdout, b"0\ntrue\n0\n1\n");
}
