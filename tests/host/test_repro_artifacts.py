"""Adversarial whole-artifact checks; fixtures are data, never runtime proof."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repro_artifacts", ROOT / "tools/m0/repro_artifacts.py")
REPRO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPRO)


class ReproArtifactTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / "build/test-tmp"
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="repro-artifacts-", dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.a, self.ma = self.fixture("a", "recipe-101-1001")
        self.b, self.mb = self.fixture("b", "recipe-202-2002")

    def fixture(self, name, cohort):
        root = self.base / name
        prefix = "artifacts/" + cohort
        source = [{"path": "source.rs", "sha256": "1" * 64}]
        digest = hashlib.sha256()
        for row in source:
            encoded = row["path"].encode()
            digest.update(len(encoded).to_bytes(8, "little"))
            digest.update(encoded)
            digest.update(row["sha256"].encode())
        manifest = {"source_sha256": digest.hexdigest(), "source_inputs": source,
                    "build_id": "2" * 64, "toolchain": "pinned-nightly", "profile": "dev",
                    "cargo_lock_sha256": "3" * 64, "loader_lock_sha256": "4" * 64,
                    "target": "x86_64-unknown-none", "fixture": None,
                    "qemu_test_exit": True, "signed": False, "supervisor": []}

        def artifact(path, data):
            relative = prefix + "/" + path
            target = root / "build/m0" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            return {"path": relative, "sha256": hashlib.sha256(data).hexdigest()}

        manifest["kernel"] = artifact("kernel.elf", b"Kernel code\0debug and symbols")
        manifest["loader"] = artifact("loader/bootloader", b"EFI loader")
        manifest["image"] = artifact("evrosion-uefi.img", b"unsigned image")
        manifest["supervisor"] = [artifact("a/app.elf", b"first full ELF\0debug A"),
                                  artifact("b/app.elf", b"second full ELF\0debug B"),
                                  artifact("catalogue.bin", b"actual catalogue"),
                                  artifact("admission.json", json.dumps({"host": name}).encode())]
        return root, manifest

    def compare(self):
        return REPRO.compare(self.a, self.ma, self.b, self.mb)

    def replace(self, manifest, root, index, contents):
        row = manifest["supervisor"][index]
        (root / "build/m0" / row["path"]).write_bytes(contents)
        row["sha256"] = hashlib.sha256(contents).hexdigest()

    def test_cohort_instance_prefixes_are_context_but_full_nested_names_are_keys(self):
        result = self.compare()
        self.assertEqual(len(result["comparisons"]), 6)
        self.assertIn("component:a/app.elf", result["comparisons"])
        self.assertIn("component:b/app.elf", result["comparisons"])
        self.assertTrue(all(row["identical"] for row in result["comparisons"].values()))
        self.assertNotEqual(result["context_metadata"]["a"][0]["sha256"],
                            result["context_metadata"]["b"][0]["sha256"])

    def test_debug_or_symbol_only_changes_are_real_failures(self):
        self.replace(self.mb, self.b, 0, b"first full ELF\0debug B")
        result = self.compare()
        self.assertFalse(result["comparisons"]["component:a/app.elf"]["identical"])

    def test_nested_same_basename_components_cannot_be_swapped(self):
        one = (self.b / "build/m0" / self.mb["supervisor"][0]["path"]).read_bytes()
        two = (self.b / "build/m0" / self.mb["supervisor"][1]["path"]).read_bytes()
        self.replace(self.mb, self.b, 0, two)
        self.replace(self.mb, self.b, 1, one)
        result = self.compare()
        self.assertFalse(result["comparisons"]["component:a/app.elf"]["identical"])
        self.assertFalse(result["comparisons"]["component:b/app.elf"]["identical"])

    def test_missing_extra_and_duplicate_target_keys_fail_closed(self):
        original = copy.deepcopy(self.mb)
        self.mb["supervisor"].pop(0)
        with self.assertRaisesRegex(ValueError, "set differs"):
            self.compare()
        self.mb = copy.deepcopy(original)
        self.mb["supervisor"].append(copy.deepcopy(self.mb["supervisor"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.compare()
        self.mb = copy.deepcopy(original)
        added = copy.deepcopy(self.mb["supervisor"][0])
        added["path"] = added["path"].replace("a/app.elf", "extra.elf")
        (self.b / "build/m0" / added["path"]).write_bytes(b"first full ELF\0debug A")
        self.mb["supervisor"].append(added)
        with self.assertRaisesRegex(ValueError, "set differs"):
            self.compare()

    def test_artifact_and_context_digests_are_verified_before_comparison(self):
        for index in (0, 3):
            path = self.b / "build/m0" / self.mb["supervisor"][index]["path"]
            old = path.read_bytes()
            path.write_bytes(b"unrecorded bytes")
            with self.assertRaisesRegex(ValueError, "digest differs"):
                self.compare()
            path.write_bytes(old)

    def test_missing_binary_and_inventory_are_rejected(self):
        removed = self.mb.pop("supervisor")
        with self.assertRaisesRegex(ValueError, "inventory missing"):
            self.compare()
        self.mb["supervisor"] = removed
        (self.b / "build/m0" / removed[0]["path"]).unlink()
        with self.assertRaisesRegex(ValueError, "artifact missing"):
            self.compare()

    def test_path_escape_outside_cohort_and_ambiguous_paths_are_rejected(self):
        original = self.mb["supervisor"][0]["path"]
        for path in ("/absolute.elf", "../escape.elf", original.replace("/a/", "/a/../a/"),
                     original.replace("/a/", "//a/"), "artifacts/another/app.elf"):
            self.mb["supervisor"][0]["path"] = path
            with self.assertRaises(ValueError):
                self.compare()

    def test_file_and_output_root_symlinks_are_rejected(self):
        p = self.b / "build/m0" / self.mb["supervisor"][0]["path"]
        old = p.read_bytes()
        p.unlink()
        target = self.b / "target.elf"
        target.write_bytes(old)
        p.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.compare()
        p.unlink()
        p.write_bytes(old)
        output = self.b / "build/m0"
        other = self.b / "elsewhere"
        output.rename(other)
        output.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.compare()

    def test_source_recipe_and_source_digest_are_independent_requirements(self):
        self.mb["build_id"] = "5" * 64
        with self.assertRaisesRegex(ValueError, "identity differs"):
            self.compare()
        self.mb["build_id"] = self.ma["build_id"]
        self.mb["source_inputs"][0]["sha256"] = "9" * 64
        with self.assertRaisesRegex(ValueError, "source-set digest"):
            self.compare()

    def test_duplicate_unsorted_source_rows_and_unknown_component_types_refuse(self):
        self.mb["source_inputs"].append(copy.deepcopy(self.mb["source_inputs"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate or unsorted"):
            self.compare()
        self.mb["source_inputs"].pop()
        row = self.mb["supervisor"][0]
        old = self.b / "build/m0" / row["path"]
        row["path"] += ".unknown"
        old.rename(self.b / "build/m0" / row["path"])
        with self.assertRaisesRegex(ValueError, "unknown component"):
            self.compare()

    def current_policy(self, manifest):
        manifest["source_input_policy"] = REPRO.CURRENT_POLICY
        fixture = manifest["fixture"] or "normal"
        recipe = (f"m0-v3\0{REPRO.CURRENT_POLICY}\0{manifest['source_sha256']}\0"
                  f"{manifest['toolchain']}\0{manifest['profile']}\0qemu-test-exit\0{fixture}")
        manifest["build_id"] = hashlib.sha256(recipe.encode()).hexdigest()

    def test_missing_historical_policy_normalizes_to_the_explicit_original_policy(self):
        self.mb["source_input_policy"] = REPRO.LEGACY_POLICY
        result = self.compare()
        self.assertEqual(result["identity"]["source_input_policy"], REPRO.LEGACY_POLICY)
        self.assertTrue(all(row["identical"] for row in result["comparisons"].values()))

    def test_current_policy_requires_its_own_bound_recipe(self):
        self.current_policy(self.ma)
        self.current_policy(self.mb)
        result = self.compare()
        self.assertEqual(result["identity"]["source_input_policy"], REPRO.CURRENT_POLICY)
        self.assertTrue(all(row["identical"] for row in result["comparisons"].values()))
        self.mb["build_id"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "scope-bound build recipe"):
            self.compare()

    def test_equal_source_digests_do_not_erase_a_different_declared_scope(self):
        self.current_policy(self.mb)
        with self.assertRaisesRegex(ValueError, "identity differs"):
            self.compare()

    def test_unknown_policy_and_archived_rows_under_current_policy_refuse(self):
        self.mb["source_input_policy"] = "unreviewed-exclusion"
        with self.assertRaisesRegex(ValueError, "unknown source-input policy"):
            self.compare()
        self.current_policy(self.ma)
        self.current_policy(self.mb)
        self.mb["source_inputs"][0]["path"] = "docs/status/evidence/previous-proof.json"
        with self.assertRaisesRegex(ValueError, "archived execution evidence"):
            self.compare()


if __name__ == "__main__":
    unittest.main()
