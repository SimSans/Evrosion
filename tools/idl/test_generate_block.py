"""Closed block-schema conformance; no device or authority acceptance claim."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("generate_block", Path(__file__).with_name("generate_block.py"))
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class BlockGeneratorTests(unittest.TestCase):
    def test_checked_in_producer_matches_exact_schema_and_template(self):
        source = GEN.SOURCE.read_bytes()
        rendered = GEN.render(source, GEN.TEMPLATE.read_text())
        self.assertEqual(rendered, GEN.OUTPUT.read_text())
        self.assertIn(hashlib.sha256(source).hexdigest(), rendered)
        self.assertNotIn("@SHA@", rendered)

    def test_rejects_every_top_level_omission_and_extension(self):
        for key in GEN.EXPECTED:
            changed = copy.deepcopy(GEN.EXPECTED)
            del changed[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                GEN.render(json.dumps(changed).encode(), "@SHA@")
        changed = dict(GEN.EXPECTED, unapproved=True)
        with self.assertRaises(ValueError):
            GEN.render(json.dumps(changed).encode(), "@SHA@")

    def test_rejects_wire_or_buffer_ownership_drift(self):
        changes = [("wire", "bytes", 16), ("wire", "flush_sector", 1),
                   ("buffer", "bytes", 4096), ("buffer", "capabilities_per_message", 1),
                   ("buffer", "ownership", "timeout_implies_release"),
                   ("transport", "automatic_retry", True),
                   ("transport", "max_outstanding", 2)]
        for section, key, value in changes:
            changed = copy.deepcopy(GEN.EXPECTED)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                GEN.render(json.dumps(changed).encode(), "@SHA@")

    def test_duplicate_and_truncated_schema_are_rejected(self):
        with self.assertRaises(ValueError):
            GEN.render(b'{"schema":1,"schema":1}', "@SHA@")
        with self.assertRaises(ValueError):
            GEN.render(b'{"wire":{"bytes":8,"bytes":8}}', "@SHA@")
        with self.assertRaises(ValueError):
            GEN.render(GEN.SOURCE.read_bytes()[:-2], "@SHA@")


if __name__ == "__main__":
    unittest.main()
