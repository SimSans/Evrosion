"""Negative checks prevent the governance gate from succeeding on broken inputs."""

from datetime import date
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from check_architecture import validate  # noqa: E402


class ArchitectureChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="evrosion-governance-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repository"
        shutil.copytree(
            ROOT,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git", ".agents", ".codex", ".ev", "target", "build", "__pycache__"
            ),
        )

    def replace(self, relative, before, after):
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        self.assertIn(before, original)
        path.write_text(original.replace(before, after), encoding="utf-8")

    def append(self, relative, text):
        with (self.root / relative).open("a", encoding="utf-8") as output:
            output.write(text)

    def errors(self, today=date(2026, 9, 20)):
        return "\n".join(validate(self.root, today=today).errors)

    def test_current_repository_passes(self):
        self.assertEqual(self.errors(), "")

    def test_missing_required_register_fails(self):
        (self.root / "architecture/INVARIANTS.md").unlink()
        self.assertIn("missing required file", self.errors())

    def test_duplicate_invariant_fails(self):
        register = self.root / "architecture/INVARIANTS.md"
        original = register.read_text(encoding="utf-8")
        for identifier in ("INV-AUTH-001", "INV-M0-001"):
            with self.subTest(identifier=identifier):
                register.write_text(original + f"\n- **{identifier} — Duplicate.**\n", encoding="utf-8")
                self.assertIn(f"duplicate invariant ID: {identifier}", self.errors())

    def test_unknown_invariant_reference_fails(self):
        self.append("architecture/GOVERNANCE.md", "\nRelated: INV-AUTH-999\n")
        self.assertIn("unknown invariant INV-AUTH-999", self.errors())

    def test_duplicate_record_id_fails(self):
        source = self.root / "architecture/exceptions/EXC-0001-temporary-bootloader.md"
        shutil.copyfile(source, source.with_name("EXC-0001-duplicate.md"))
        self.assertIn("duplicate record ID: EXC-0001", self.errors())

    def test_broken_file_and_heading_links_fail(self):
        self.append("README.md", "\n[Missing](absent.md)\n[Heading](README.md#no-such-heading)\n")
        errors = self.errors()
        self.assertIn("broken local link absent.md", errors)
        self.assertIn("broken heading link README.md#no-such-heading", errors)

    def test_code_examples_are_not_live_links_or_definitions(self):
        self.append("README.md", "\n```markdown\n[Example](absent.md)\n- **INV-AUTH-001 — Example.**\n```\n")
        self.assertEqual(self.errors(), "")

    def test_exception_requires_owner(self):
        path = "architecture/exceptions/EXC-0001-temporary-bootloader.md"
        text = (self.root / path).read_text(encoding="utf-8")
        owner = next(line for line in text.splitlines() if line.startswith("Owner:"))
        self.replace(path, owner, "")
        self.assertIn("missing fields: Owner", self.errors())

    def test_expiry_date_is_inclusive(self):
        self.replace(
            "architecture/exceptions/EXC-0001-temporary-bootloader.md",
            "Expiry trigger: boot-contract-preview", "Expiry trigger: date:2026-09-20",
        )
        self.assertEqual(self.errors(today=date(2026, 9, 19)), "")
        self.assertIn("EXC-0001: expired exception", self.errors(today=date(2026, 9, 20)))
        self.assertIn("EXC-0001: expired exception", self.errors(today=date(2026, 9, 21)))

    def test_boot_exception_expires_at_preview_and_later(self):
        state = self.root / "architecture/status.toml"
        original = state.read_text(encoding="utf-8")
        for maturity in ("Preview", "Stable", "Deprecated", "Removed"):
            with self.subTest(maturity=maturity):
                state.write_text(original.replace('"Internal"', f'"{maturity}"'), encoding="utf-8")
                self.assertIn("EXC-0001: expired exception", self.errors())

    def test_each_production_declaration_expires_host_exception(self):
        state = self.root / "architecture/status.toml"
        original = state.read_text(encoding="utf-8")
        for flag in ("release_ci_production_grade", "reproducibility_production_grade"):
            with self.subTest(flag=flag):
                state.write_text(original.replace(f"{flag} = false", f"{flag} = true"), encoding="utf-8")
                self.assertIn("EXC-0002: expired exception", self.errors())

    def test_milestone_expiry_compares_numbers(self):
        state = (self.root / "architecture/status.toml").read_text()
        current = tomllib.loads(state)["milestone"]
        self.replace("architecture/status.toml", f'milestone = "{current}"', 'milestone = "M9"')
        self.replace(
            "architecture/exceptions/EXC-0001-temporary-bootloader.md",
            "Expiry trigger: boot-contract-preview", "Expiry trigger: milestone:M10",
        )
        self.assertEqual(self.errors(), "")
        self.replace("architecture/status.toml", 'milestone = "M9"', 'milestone = "M10"')
        self.assertIn("EXC-0001: expired exception", self.errors())

    def test_unknown_expiry_trigger_fails_closed(self):
        self.replace(
            "architecture/exceptions/EXC-0001-temporary-bootloader.md",
            "Expiry trigger: boot-contract-preview", "Expiry trigger: whenever",
        )
        self.assertIn("unknown expiry trigger", self.errors())

    def test_explicitly_expired_exception_is_reported(self):
        self.replace("architecture/exceptions/EXC-0001-temporary-bootloader.md", "Status: Active", "Status: Expired")
        report = validate(self.root)
        self.assertTrue(any("EXC-0001: Expired" in notice for notice in report.notices))
        self.assertTrue(any("expired exception" in error for error in report.errors))

    def test_register_cannot_hide_an_active_record(self):
        self.replace("architecture/exceptions/REGISTER.md", "| Active |", "| Resolved |")
        self.assertIn("register IDs/statuses do not match", self.errors())

    def test_source_change_requires_inventory_update(self):
        self.append("architecture/plans/foundations/foundational-requirements.txt", "\nChanged\n")
        self.assertIn("source inventory checksum mismatch", self.errors())

    def test_dependency_alias_cannot_escape_boot_adapter(self):
        manifest = self.root / "tools/ev/Cargo.toml"
        text = manifest.read_text(encoding="utf-8")
        section = "[dev-dependencies]"
        alias = 'renamed = { package = "bootloader_api", version = "=0.11.17" }\n'
        if section in text:
            manifest.write_text(text.replace(section, section + "\n" + alias, 1), encoding="utf-8")
        else:
            self.append("tools/ev/Cargo.toml", "\n" + section + "\n" + alias)
        self.assertEqual(
            tomllib.loads(manifest.read_text(encoding="utf-8"))["dev-dependencies"]["renamed"],
            {"package": "bootloader_api", "version": "=0.11.17"},
        )
        self.assertIn("bootloader_api exceeds EXC-0001 scope", self.errors())

    def test_cli_returns_failure_for_invalid_repository(self):
        self.append("README.md", "\n[Missing](absent.md)\n")
        output = subprocess.run(
            [sys.executable, str(ROOT / "tools/check_architecture.py"), "--root", str(self.root)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(output.returncode, 1)
        self.assertIn("broken local link absent.md", output.stdout)


if __name__ == "__main__":
    unittest.main()
