//! Versioned compilation inputs. Archived execution reports are outputs; actual
//! compiler/generator sources and reviewed fixtures remain ordinary inputs.
use super::{Result, SourceInput};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceInputPolicy {
    /// Historical manifests omitted the policy and enumerated all Git files.
    #[default]
    #[serde(rename = "git-working-tree-v1")]
    LegacyV1,
    #[serde(rename = "git-working-tree-v2-no-archived-evidence")]
    WithoutArchivedEvidenceV2,
}

impl SourceInputPolicy {
    pub const CURRENT: Self = Self::WithoutArchivedEvidenceV2;

    pub fn name(self) -> &'static str {
        match self {
            Self::LegacyV1 => "git-working-tree-v1",
            Self::WithoutArchivedEvidenceV2 => "git-working-tree-v2-no-archived-evidence",
        }
    }

    pub(crate) fn includes(self, path: &str) -> bool {
        self == Self::LegacyV1 || !path.starts_with("docs/status/evidence/")
    }

    pub(crate) fn validate_rows(self, rows: &[SourceInput]) -> Result<()> {
        if self == Self::CURRENT && rows.is_empty() {
            return Err("current build-input policy requires a nonempty source inventory".into());
        }
        let mut previous: Option<&str> = None;
        for row in rows {
            if row.path.is_empty()
                || row
                    .path
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
            {
                return Err("source-input path must be canonical and relative".into());
            }
            if previous.is_some_and(|old| old >= row.path.as_str()) {
                return Err("source-input paths must be sorted and unique".into());
            }
            if row.sha256.len() != 64
                || !row
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("source-input SHA-256 must be canonical lowercase hex".into());
            }
            if !self.includes(&row.path) {
                return Err(
                    "archived execution evidence is outside the declared build-input policy".into(),
                );
            }
            previous = Some(&row.path);
        }
        Ok(())
    }

    pub(crate) fn build_id(
        self,
        source: &str,
        toolchain: &str,
        profile: &str,
        fixture: Option<&str>,
    ) -> String {
        let fixture = fixture.unwrap_or("normal");
        let recipe = match self {
            Self::LegacyV1 => {
                format!("m0-v2\0{source}\0{toolchain}\0{profile}\0qemu-test-exit\0{fixture}")
            }
            Self::WithoutArchivedEvidenceV2 => format!(
                "m0-v3\0{}\0{source}\0{toolchain}\0{profile}\0qemu-test-exit\0{fixture}",
                self.name()
            ),
        };
        format!("{:x}", Sha256::digest(recipe))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, process::Command};

    struct GitTree(PathBuf);
    impl GitTree {
        fn git(&self) -> Command {
            let mut command = Command::new("git");
            // These tests mutate only their new private repository, regardless
            // of a caller's worktree/index overrides or global Git templates.
            for (key, _) in std::env::vars_os() {
                if key.to_str().is_some_and(|key| key.starts_with("GIT_")) {
                    command.env_remove(key);
                }
            }
            command
                .current_dir(&self.0)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_TEMPLATE_DIR", "")
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                ]);
            command
        }
        fn new() -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap();
            let tree = Self(
                super::super::unique_directory(&root.join("build/test-tmp"), "input-policy-tests")
                    .unwrap(),
            );
            let status = tree.git().args(["init", "-q"]).status().unwrap();
            assert!(status.success());
            tree
        }
        fn write(&self, path: &str, data: &[u8]) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, data).unwrap();
        }
        fn inputs(&self) -> (String, Vec<SourceInput>) {
            super::super::source_inputs(&self.0).unwrap()
        }
        fn track(&self, path: &str) {
            assert!(
                self.git()
                    .args(["add", "--", path])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
    impl Drop for GitTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn actual_git_archive_creation_change_and_removal_do_not_rewrite_compilation_inputs() {
        let tree = GitTree::new();
        tree.write("kernel/src/main.rs", b"actual compiler source");
        let original = tree.inputs();
        tree.write(
            "docs/status/evidence/execution.json",
            b"first retained execution",
        );
        assert_eq!(tree.inputs(), original);
        tree.track("docs/status/evidence/execution.json");
        assert_eq!(tree.inputs(), original);
        tree.write(
            "docs/status/evidence/execution.json",
            b"new evidence of the same compiled source",
        );
        assert_eq!(tree.inputs(), original);
        fs::remove_file(tree.0.join("docs/status/evidence/execution.json")).unwrap();
        assert_eq!(tree.inputs(), original);
    }

    #[test]
    fn source_generator_template_fixture_and_neighboring_docs_remain_actual_inputs() {
        let tree = GitTree::new();
        let paths = [
            " source with spaces.rs ",
            "kernel/src/main.rs",
            "tools/generator.py",
            "boot/template.bin",
            "tests/fixtures/input.raw",
            "architecture/plan.md",
            "docs/development/guide.md",
            "docs/status/evidence.txt",
            "docs/status/evidence-extra/report.json",
            "nested/docs/status/evidence/report.json",
        ];
        for path in paths {
            tree.write(path, b"original input");
        }
        let original = tree.inputs();
        assert_eq!(original.1.len(), paths.len());
        for path in paths {
            tree.write(path, b"meaningfully changed input");
            assert_ne!(tree.inputs().0, original.0, "lost actual input: {path}");
            tree.write(path, b"original input");
            assert_eq!(tree.inputs(), original);
        }
    }

    #[test]
    fn declared_scope_rows_refuse_archives_ambiguous_paths_duplicates_and_bad_digests() {
        let source = |path: &str| SourceInput {
            path: path.into(),
            sha256: "1".repeat(64),
        };
        let archive = [source("docs/status/evidence/old.json")];
        assert!(SourceInputPolicy::LegacyV1.validate_rows(&archive).is_ok());
        assert!(SourceInputPolicy::CURRENT.validate_rows(&archive).is_err());
        assert!(SourceInputPolicy::CURRENT.validate_rows(&[]).is_err());
        for path in ["/absolute", "a//b", "a/../b", "./source", ""] {
            assert!(
                SourceInputPolicy::CURRENT
                    .validate_rows(&[source(path)])
                    .is_err()
            );
        }
        for rows in [
            vec![source("b"), source("a")],
            vec![source("a"), source("a")],
        ] {
            assert!(SourceInputPolicy::CURRENT.validate_rows(&rows).is_err());
        }
        let mut bad = source("source.rs");
        bad.sha256 = "F".repeat(64);
        assert!(SourceInputPolicy::CURRENT.validate_rows(&[bad]).is_err());
    }

    #[test]
    fn known_historical_recipe_stays_exact_and_current_policy_binds_new_domain() {
        let old = SourceInputPolicy::LegacyV1.build_id(
            "8919255f89cd087dcbdcf5c5db5d53823407479018f1804a8b9d7e5c66e44421",
            "nightly-2026-07-10",
            "dev",
            None,
        );
        // Actual retained earlier public-baseline build, not a fabricated VM.
        assert_eq!(
            old,
            "f4b4d2627ace1e0613807a56bbcccfa0ece9dd0491a5a983af039346e2e0be24"
        );
        assert_ne!(
            old,
            SourceInputPolicy::CURRENT.build_id(
                "8919255f89cd087dcbdcf5c5db5d53823407479018f1804a8b9d7e5c66e44421",
                "nightly-2026-07-10",
                "dev",
                None
            )
        );
        assert!(serde_json::from_str::<SourceInputPolicy>("\"unknown-policy\"").is_err());
        assert_eq!(
            serde_json::to_string(&SourceInputPolicy::CURRENT).unwrap(),
            "\"git-working-tree-v2-no-archived-evidence\""
        );
    }

    #[test]
    fn manifest_legacy_default_is_explicit_and_unknown_or_false_scope_is_rejected() {
        let mut value = serde_json::json!({
            "schema":1,"build_id":"test","source_revision":null,"source_dirty":true,
            "source_sha256":"test","source_inputs":[{
                "path":"docs/status/evidence/historical.json","sha256":"1".repeat(64)
            }],"toolchain":"test","rustc":"test","cargo":"test",
            "cargo_lock_sha256":"test","loader_lock_sha256":"test","profile":"dev",
            "declared_environment":{},"target":"x86_64-unknown-none",
            "qemu_test_exit":true,"fixture":null,"signed":false,
            "kernel":{"path":"test","sha256":"test"},
            "image":{"path":"test","sha256":"test"},
            "loader":{"path":"test","sha256":"test"},
            "image_builder":{"path":"test","sha256":"test"}
        });
        let old: super::super::Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(old.source_input_policy, SourceInputPolicy::LegacyV1);
        old.validate_policy_rows().unwrap();
        value["source_input_policy"] = serde_json::json!(SourceInputPolicy::CURRENT.name());
        let false_scope: super::super::Manifest = serde_json::from_value(value.clone()).unwrap();
        assert!(false_scope.validate_policy_rows().is_err());
        value["source_input_policy"] = serde_json::json!("unreviewed-policy");
        assert!(serde_json::from_value::<super::super::Manifest>(value).is_err());
    }
}
