"""Document control directions, grant capabilities and frame ownership meaning."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import generate


class DocumentTestGeneration(unittest.TestCase):
    def setUp(self):
        self.source = generate.DOCUMENT_TEST_SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_binding_and_old_note_schema_keep_distinct_meanings(self):
        self.assertEqual(generate.DOCUMENT_TEST_OUTPUT.read_text(), generate.render_document_test(self.source))
        with self.assertRaises(ValueError):
            generate.render_document_test(generate.SESSION_NOTE_SOURCE.read_bytes())
        with self.assertRaises(ValueError):
            generate.render_session_note(self.source)

    def test_keys_flags_and_provenance_cannot_be_reinterpreted(self):
        for field, replacement in [('version', True), ('maturity', 'Stable')]:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.assertRaises(ValueError):
                generate.render_document_test(json.dumps(value).encode())
        for field in ['magic','version_byte','commands','reserved_zero']:
            value = copy.deepcopy(self.value)
            value['wire'][field] = None
            with self.assertRaises(ValueError):
                generate.render_document_test(json.dumps(value).encode())

    def test_invalid_last_control_schema_cannot_partially_update_other_interfaces(self):
        parent = generate.ROOT / 'build/test-tmp'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as name:
            directory = Path(name)
            bad = directory / 'bad.json'
            bad.write_text('{}')
            names = ['OUTPUT', 'CAP_OUTPUT', 'PROVIDER_OUTPUT', 'APP_DATA_OUTPUT',
                     'SESSION_NOTE_OUTPUT', 'DOCUMENT_OUTPUT', 'DOCUMENT_CONTROL_OUTPUT', 'FOCUSED_INPUT_OUTPUT', 'DOCUMENT_TEST_OUTPUT']
            paths = [directory / (name + '.rs') for name in names]
            for name, path in zip(names, paths):
                path.write_text('preserved-' + name)
            before = [path.read_bytes() for path in paths]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(generate, 'DOCUMENT_TEST_SOURCE', bad))
                stack.enter_context(patch('sys.argv', ['generate.py']))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                for name, path in zip(names, paths):
                    stack.enter_context(patch.object(generate, name, path))
                self.assertEqual(generate.main(), 1)
            self.assertEqual([path.read_bytes() for path in paths], before)


if __name__ == '__main__':
    unittest.main()
