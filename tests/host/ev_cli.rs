use std::process::Command;

#[test]
fn help_describes_the_current_slice() {
    let output = Command::new(env!("CARGO_BIN_EXE_ev"))
        .arg("--help")
        .output()
        .expect("ev must launch");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help must be UTF-8");
    assert!(help.contains("Evrosion development frontend"));
    assert!(help.contains("cargo ev doctor"));
    assert!(help.contains("cargo ev test storage-generation"));
}

#[test]
fn invalid_doctor_arguments_have_usage_exit_status() {
    for arguments in [
        vec!["doctor", "--root"],
        vec!["doctor", "--force"],
        vec!["doctor", "--root", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ev"))
            .args(arguments)
            .output()
            .expect("ev must launch");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn missing_workspace_is_a_diagnostic_failure() {
    let output = Command::new(env!("CARGO_BIN_EXE_ev"))
        .args(["doctor", "--root", "Cargo.toml"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("ev must launch");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("FAIL workspace"));
}

#[test]
fn unimplemented_command_cannot_report_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_ev"))
        .arg("not-a-command")
        .output()
        .expect("ev must launch");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
