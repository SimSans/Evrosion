"""Document IDL bounds/semantics and all-or-none validation before generation."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import generate


class DocumentGeneration(unittest.TestCase):
    def setUp(self):
        self.source = generate.DOCUMENT_SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_checked_binding_matches_schema_and_existing_file_contract_is_unchanged(self):
        self.assertEqual(generate.DOCUMENT_OUTPUT.read_text(), generate.render_document(self.source))
        path = generate.ROOT / 'idl/ev.internal.file.v1.json'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         '27bbabb7abe7378cda0090a7511b30c8d5fafeb98e5176864555f85726b7bc74')
        with self.assertRaises(ValueError):
            generate.render_session_note(self.source)
        with self.assertRaises(ValueError):
            generate.render_document(generate.SESSION_NOTE_SOURCE.read_bytes())

    def test_layout_semantics_authority_and_uncertainty_cannot_silently_change(self):
        changes = [(('version',), True), (('snapshot', 'bytes'), 512),
                   (('snapshot', 'text_bytes'), 225), (('snapshot', 'fields', 'cursor_u16'), 18),
                   (('snapshot', 'access', 'Read'), 2),
                   (('text', 'cursor_and_anchor'), 'arbitrary_byte_offsets'),
                   (('text', 'unsupported'), 'replace_with_empty'),
                   (('semantics', 'saved'), 'sent'),
                   (('semantics', 'authority'), 'wire_choice_is_capability'),
                   (('transport', 'max_capabilities'), 1),
                   (('transport', 'timeout'), 'retry_new_counter')]
        for path, replacement in changes:
            value = copy.deepcopy(self.value)
            field = value
            for name in path[:-1]:
                field = field[name]
            field[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate.render_document(json.dumps(value).encode())
        for malformed in [b'{}', b'[]', b'null', self.source + b'{}',
                          self.source.replace(b'"schema": 1,', b'"schema": 1, "schema": 1,')]:
            with self.assertRaises(ValueError):
                generate.render_document(malformed)

    def test_invalid_last_document_schema_preserves_all_earlier_bindings(self):
        parent = generate.ROOT / 'build/test-tmp'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as name:
            directory = Path(name)
            bad = directory / 'bad.json'
            bad.write_text('{}')
            names = ['OUTPUT', 'CAP_OUTPUT', 'PROVIDER_OUTPUT', 'APP_DATA_OUTPUT',
                     'SESSION_NOTE_OUTPUT', 'DOCUMENT_OUTPUT']
            outputs = [directory / (name + '.rs') for name in names]
            for name, path in zip(names, outputs):
                path.write_text('preserved-' + name)
            before = [path.read_bytes() for path in outputs]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(generate, 'DOCUMENT_SOURCE', bad))
                stack.enter_context(patch('sys.argv', ['generate.py']))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                for name, path in zip(names, outputs):
                    stack.enter_context(patch.object(generate, name, path))
                self.assertEqual(generate.main(), 1)
            self.assertEqual([path.read_bytes() for path in outputs], before)


if __name__ == '__main__':
    unittest.main()
