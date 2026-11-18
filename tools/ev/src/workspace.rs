//! Explicit M8 frontend. Native bytes/typed admission are separate from actual
//! VM, authority/backing, device, UI consent and recovery qualification.
#[cfg(feature = "workspace")]
mod apps;
#[cfg(feature = "workspace")]
mod bundle;
#[cfg(feature = "workspace")]
mod packages;
#[cfg(feature = "workspace")]
mod restart;
#[cfg(feature = "workspace")]
mod run;
#[cfg(feature = "workspace")]
mod scenario;
#[cfg(feature = "workspace")]
mod template;
use std::{ffi::OsString, path::PathBuf};
/// Explicit producer declarations for actual implementations. A resource-shape
/// match or a dependency on the SDK does not imply A1 implementation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SemanticDeclarations {
    pub files: bool,
    pub editor: bool,
    pub inspector: bool,
    pub editor_candidate: bool,
}
impl SemanticDeclarations {
    #[cfg(feature = "workspace")]
    fn ordered(self) -> [bool; 4] {
        [
            self.files,
            self.editor,
            self.inspector,
            self.editor_candidate,
        ]
    }
}
pub const HELP: &str = "Usage: cargo run -p ev --features workspace -- workspace packages --root PATH --output NEW_DIR --files ELF --editor ELF --inspector ELF [--editor-candidate ELF]\n       ... workspace prepare|build --root PATH --output NEW_DIR --artifacts INPUT_JSON\n       ... workspace preview --root PATH --prepared DIR [--timeout SECONDS] [--headless] [--host-provision-new | --owned-data-template PATH --owned-data-template-sha256 HEX] [--ovmf-code PATH --ovmf-vars PATH] [--scenario files-basic|files-a1|files-shutdown|files-restart|inspector-own|inspector-reader|large-io|large-io-finite|legacy-owner]\n       ... workspace rebuild --root PATH --output NEW_DIR [--provision-new]\nA1 producer declarations are explicit --files-semantic-tree/--editor-semantic-tree/--inspector-semantic-tree/--editor-candidate-semantic-tree flags for packages, or semantic_tree booleans in artifact JSON.\nAll paths are explicit Internal inputs. Preview creates only a new owned96MiB disk and private OVMF variables. legacy-owner requires an explicit verified owned template, performs no edit/Save and checks the whole disk unchanged after VM exit. No VM success or update/installer acceptance follows from packaging.\n";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Packages,
    Prepare,
    Build,
    Preview,
    Rebuild,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub operation: Operation,
    pub root: PathBuf,
    pub output: Option<PathBuf>,
    pub prepared: Option<PathBuf>,
    pub artifacts: Option<PathBuf>,
    pub files: Option<PathBuf>,
    pub editor: Option<PathBuf>,
    pub inspector: Option<PathBuf>,
    pub editor_candidate: Option<PathBuf>,
    pub timeout: u64,
    pub headless: bool,
    pub provision_new: bool,
    pub host_provision_new: bool,
    pub owned_data_template: Option<PathBuf>,
    pub owned_data_template_sha256: Option<String>,
    pub ovmf_code: Option<PathBuf>,
    pub ovmf_vars: Option<PathBuf>,
    pub scenario: Option<String>,
    pub semantic_tree: SemanticDeclarations,
}
pub fn parse(args: &[OsString]) -> Result<Options, String> {
    let Some(command) = args.first().and_then(|s| s.to_str()) else {
        return Err(HELP.into());
    };
    let operation = match command {
        "packages" => Operation::Packages,
        "prepare" => Operation::Prepare,
        "build" => Operation::Build,
        "preview" => Operation::Preview,
        "rebuild" => Operation::Rebuild,
        _ => return Err(HELP.into()),
    };
    let mut result = Options {
        operation,
        root: PathBuf::new(),
        output: None,
        prepared: None,
        artifacts: None,
        files: None,
        editor: None,
        inspector: None,
        editor_candidate: None,
        timeout: 60,
        headless: false,
        provision_new: false,
        host_provision_new: false,
        owned_data_template: None,
        owned_data_template_sha256: None,
        ovmf_code: None,
        ovmf_vars: None,
        scenario: None,
        semantic_tree: SemanticDeclarations::default(),
    };
    let mut root = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut iter = args[1..].iter();
    while let Some(flag) = iter.next() {
        let flag = flag.to_str().ok_or("workspace flags must be UTF8")?;
        if !seen.insert(flag) {
            return Err(format!("duplicate workspace option {flag}"));
        }
        match flag {
            "--headless" => result.headless = true,
            "--host-provision-new" => result.host_provision_new = true,
            "--provision-new" => result.provision_new = true,
            "--files-semantic-tree" => result.semantic_tree.files = true,
            "--editor-semantic-tree" => result.semantic_tree.editor = true,
            "--inspector-semantic-tree" => result.semantic_tree.inspector = true,
            "--editor-candidate-semantic-tree" => result.semantic_tree.editor_candidate = true,
            "--root"
            | "--output"
            | "--prepared"
            | "--artifacts"
            | "--files"
            | "--editor"
            | "--inspector"
            | "--editor-candidate"
            | "--timeout"
            | "--ovmf-code"
            | "--ovmf-vars"
            | "--scenario"
            | "--owned-data-template"
            | "--owned-data-template-sha256" => {
                let value = iter
                    .next()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                match flag {
                    "--owned-data-template" => {
                        result.owned_data_template = Some(PathBuf::from(value))
                    }
                    "--owned-data-template-sha256" => {
                        let hash = value.to_str().ok_or("template hash must be UTF8")?;
                        if hash.len() != 64
                            || !hash
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        {
                            return Err("template SHA must be64 lowercase hexadecimal bytes".into());
                        }
                        result.owned_data_template_sha256 = Some(hash.into());
                    }
                    "--scenario" => {
                        if value != "files-basic"
                            && value != "files-a1"
                            && value != "files-shutdown"
                            && value != "files-restart"
                            && value != "inspector-own"
                            && value != "inspector-reader"
                            && value != "large-io"
                            && value != "large-io-finite"
                            && value != "legacy-owner"
                        {
                            return Err(
                                "only bounded files-basic/files-a1/files-shutdown/files-restart/inspector-own/inspector-reader/large-io/large-io-finite/legacy-owner scenarios are supported".into(),
                            );
                        }
                        result.scenario =
                            Some(value.to_str().ok_or("scenario must be UTF8")?.into());
                    }
                    "--ovmf-code" => result.ovmf_code = Some(PathBuf::from(value)),
                    "--ovmf-vars" => result.ovmf_vars = Some(PathBuf::from(value)),
                    "--root" => root = Some(PathBuf::from(value)),
                    "--output" => result.output = Some(PathBuf::from(value)),
                    "--prepared" => result.prepared = Some(PathBuf::from(value)),
                    "--artifacts" => result.artifacts = Some(PathBuf::from(value)),
                    "--files" => result.files = Some(PathBuf::from(value)),
                    "--editor" => result.editor = Some(PathBuf::from(value)),
                    "--inspector" => result.inspector = Some(PathBuf::from(value)),
                    "--editor-candidate" => result.editor_candidate = Some(PathBuf::from(value)),
                    _ => {
                        let n = value.to_str().ok_or("timeout must be UTF8")?;
                        if n.is_empty()
                            || !n.bytes().all(|b| b.is_ascii_digit())
                            || n.starts_with('0')
                        {
                            return Err("timeout must be canonical1..600 seconds".into());
                        }
                        result.timeout = n.parse().map_err(|_| "invalid workspace timeout")?;
                        if !(1..=600).contains(&result.timeout) {
                            return Err("workspace timeout must be1..600".into());
                        }
                    }
                }
            }
            _ => return Err(format!("unknown workspace option {flag}")),
        }
    }
    result.root = root.ok_or("workspace requires explicit --root PATH")?;
    let allowed: &[&str] = match operation {
        Operation::Packages => &[
            "--root",
            "--output",
            "--files",
            "--editor",
            "--inspector",
            "--editor-candidate",
            "--files-semantic-tree",
            "--editor-semantic-tree",
            "--inspector-semantic-tree",
            "--editor-candidate-semantic-tree",
        ],
        Operation::Prepare | Operation::Build => &["--root", "--output", "--artifacts"],
        Operation::Preview => &[
            "--root",
            "--prepared",
            "--timeout",
            "--headless",
            "--host-provision-new",
            "--ovmf-code",
            "--ovmf-vars",
            "--scenario",
            "--owned-data-template",
            "--owned-data-template-sha256",
        ],
        Operation::Rebuild => &[
            "--root",
            "--output",
            "--provision-new",
            "--files-semantic-tree",
            "--inspector-semantic-tree",
        ],
    };
    if seen.iter().any(|f| !allowed.contains(f)) {
        return Err("workspace option does not apply to selected operation".into());
    }
    match operation {
        Operation::Packages
            if result.output.is_none()
                || result.files.is_none()
                || result.editor.is_none()
                || result.inspector.is_none() =>
        {
            return Err("packages requires output/files/editor/inspector paths".into());
        }
        Operation::Prepare | Operation::Build
            if result.output.is_none() || result.artifacts.is_none() =>
        {
            return Err("prepare/build requires output/artifacts paths".into());
        }
        Operation::Preview if result.prepared.is_none() => {
            return Err("preview requires prepared directory".into());
        }
        Operation::Rebuild if result.output.is_none() => {
            return Err("rebuild requires output directory".into());
        }
        _ => {}
    }
    if result.owned_data_template.is_some() != result.owned_data_template_sha256.is_some()
        || result.owned_data_template.is_some() && result.host_provision_new
    {
        return Err(
            "owned template requires its expected SHA and excludes host provisioning".into(),
        );
    }
    if let Some(scenario) = result.scenario.as_deref() {
        let minimum = if scenario == "large-io-finite" {
            600
        } else if matches!(
            scenario,
            "files-a1" | "legacy-owner" | "inspector-own" | "inspector-reader" | "files-restart"
        ) {
            300
        } else {
            120
        };
        let template = matches!(scenario, "large-io" | "large-io-finite" | "legacy-owner");
        if result.timeout < minimum
            || template != result.owned_data_template.is_some()
            || (!template && !result.host_provision_new)
        {
            return Err(format!(
                "{scenario} requires >={minimum} seconds and {}",
                if template {
                    "an explicit verified owned template without provisioning"
                } else {
                    "explicit host-provision-new"
                }
            ));
        }
    }
    Ok(result)
}
pub fn execute(args: &[OsString]) -> Result<(), String> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    let options = parse(args)?;
    #[cfg(feature = "workspace")]
    {
        match options.operation {
            Operation::Packages => packages::command(&options),
            Operation::Prepare => bundle::command(&options, false),
            Operation::Build => bundle::command(&options, true),
            Operation::Preview => run::preview(&options),
            Operation::Rebuild => bundle::rebuild(&options),
        }
    }
    #[cfg(not(feature = "workspace"))]
    {
        let _ = options;
        Err("workspace frontend requires Cargo feature workspace; legacy frontend remains available".into())
    }
}
/// Distinct external application workflow; fixed built-in package identities
/// and selected resource shapes remain separate.
pub fn execute_app(args: &[OsString]) -> Result<(), String> {
    #[cfg(feature = "workspace")]
    {
        apps::execute(args)
    }
    #[cfg(not(feature = "workspace"))]
    {
        let _ = args;
        Err("app frontend requires feature workspace".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(words: &[&str]) -> Result<Options, String> {
        parse(&words.iter().map(OsString::from).collect::<Vec<_>>())
    }
    #[test]
    fn own_inspector_requires_new_owned_disk_and_at_least300_seconds() {
        for profile in ["inspector-own", "inspector-reader"] {
            let base = [
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                profile,
                "--timeout",
            ];
            for (seconds, good) in [("299", false), ("300", true), ("600", true)] {
                let mut args = base.to_vec();
                args.extend([seconds, "--host-provision-new"]);
                assert_eq!(p(&args).is_ok(), good);
            }
            let mut unowned = base.to_vec();
            unowned.push("300");
            assert!(p(&unowned).is_err());
            unowned.extend([
                "--owned-data-template",
                "data",
                "--owned-data-template-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]);
            assert!(p(&unowned).is_err());
        }
    }
    #[test]
    fn files_shutdown_requires_explicit_new_owned_disk_and_original_finite_observation() {
        for seconds in ["120", "300", "600"] {
            assert!(
                p(&[
                    "preview",
                    "--root",
                    "r",
                    "--prepared",
                    "p",
                    "--scenario",
                    "files-shutdown",
                    "--timeout",
                    seconds,
                    "--host-provision-new"
                ])
                .is_ok()
            );
        }
        for args in [
            vec![
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "files-shutdown",
                "--timeout",
                "119",
                "--host-provision-new",
            ],
            vec![
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "files-shutdown",
                "--timeout",
                "120",
            ],
            vec![
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "files-shutdown",
                "--timeout",
                "120",
                "--owned-data-template",
                "data",
                "--owned-data-template-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
        ] {
            assert!(p(&args).is_err());
        }
    }
    #[test]
    fn explicit_paths_and_operation_scopes_are_required() {
        assert!(
            p(&[
                "packages",
                "--root",
                "r",
                "--output",
                "o",
                "--files",
                "f",
                "--editor",
                "e",
                "--inspector",
                "i"
            ])
            .is_ok()
        );
        for args in [
            vec![
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--timeout",
                "0",
            ],
            vec!["preview", "--root", "r", "--prepared", "p", "--files", "f"],
            vec!["prepare", "--root", "r", "--output", "o"],
            vec![
                "prepare",
                "--root",
                "r",
                "--root",
                "x",
                "--output",
                "o",
                "--artifacts",
                "a",
            ],
        ] {
            assert!(p(&args).is_err());
        }
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "files-basic",
                "--timeout",
                "120",
                "--host-provision-new"
            ])
            .is_ok()
        );
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "files-basic"
            ])
            .is_err()
        );
        for seconds in ["120", "299"] {
            assert!(
                p(&[
                    "preview",
                    "--root",
                    "r",
                    "--prepared",
                    "p",
                    "--scenario",
                    "files-a1",
                    "--timeout",
                    seconds,
                    "--host-provision-new"
                ])
                .is_err()
            );
        }
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "files-a1",
                "--timeout",
                "300",
                "--host-provision-new"
            ])
            .is_ok()
        );
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "unknown",
                "--host-provision-new"
            ])
            .is_err()
        );
    }
    #[test]
    fn template_is_explicit_paired_and_excludes_format_and_basic_creation() {
        let hash = "a".repeat(64);
        let base = [
            "preview",
            "--root",
            "r",
            "--prepared",
            "p",
            "--owned-data-template",
            "t",
            "--owned-data-template-sha256",
            hash.as_str(),
        ];
        assert!(p(&base).is_ok());
        let mut large = base.to_vec();
        large.extend(["--scenario", "large-io", "--timeout", "120"]);
        assert!(p(&large).is_ok());
        let mut finite = base.to_vec();
        finite.extend(["--scenario", "large-io-finite", "--timeout", "600"]);
        assert!(p(&finite).is_ok());
        let mut short = base.to_vec();
        short.extend(["--scenario", "large-io-finite", "--timeout", "300"]);
        assert!(p(&short).is_err());
        for tail in [
            vec!["--host-provision-new"],
            vec!["--scenario", "files-basic", "--timeout", "120"],
        ] {
            let mut args = base.to_vec();
            args.extend(tail);
            assert!(p(&args).is_err());
        }
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--owned-data-template",
                "t"
            ])
            .is_err()
        );
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--owned-data-template",
                "t",
                "--owned-data-template-sha256",
                "AA"
            ])
            .is_err()
        );
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--scenario",
                "large-io",
                "--host-provision-new",
                "--timeout",
                "120"
            ])
            .is_err()
        );
    }
    #[test]
    fn legacy_owner_requires_verified_template_and_never_provisions() {
        let hash = "a".repeat(64);
        let base = [
            "preview",
            "--root",
            "r",
            "--prepared",
            "p",
            "--scenario",
            "legacy-owner",
            "--timeout",
            "300",
        ];
        assert!(p(&base).is_err());
        let mut new = base.to_vec();
        new.push("--host-provision-new");
        assert!(p(&new).is_err());
        let mut template = base.to_vec();
        template.extend([
            "--owned-data-template",
            "old",
            "--owned-data-template-sha256",
            hash.as_str(),
        ]);
        assert!(p(&template).is_ok());
        let mut too_short = template.clone();
        too_short[8] = "299";
        assert!(p(&too_short).is_err());
        let mut too_long = template.clone();
        too_long[8] = "601";
        assert!(p(&too_long).is_err());
        template.push("--host-provision-new");
        assert!(p(&template).is_err());
    }
    #[test]
    fn semantic_producer_declarations_are_strict_and_never_default_from_shape() {
        let declarations: SemanticDeclarations = serde_json::from_str("{}").unwrap();
        assert_eq!(declarations, SemanticDeclarations::default());
        for malformed in [
            r#"{"editor":1}"#,
            r#"{"editor":true,"editor":false}"#,
            r#"{"application":true}"#,
        ] {
            assert!(serde_json::from_str::<SemanticDeclarations>(malformed).is_err());
        }
        let parsed = p(&[
            "packages",
            "--root",
            "r",
            "--output",
            "o",
            "--files",
            "f",
            "--editor",
            "e",
            "--inspector",
            "i",
            "--editor-semantic-tree",
        ])
        .unwrap();
        assert!(parsed.semantic_tree.editor);
        assert!(
            !parsed.semantic_tree.files
                && !parsed.semantic_tree.inspector
                && !parsed.semantic_tree.editor_candidate
        );
        assert!(
            p(&[
                "preview",
                "--root",
                "r",
                "--prepared",
                "p",
                "--editor-semantic-tree"
            ])
            .is_err()
        );
    }
}
