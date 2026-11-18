"""Closed note protocol semantics and atomic generation; no runtime proof."""
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


class SessionNoteGeneration(unittest.TestCase):
    def setUp(self):
        self.source = generate.SESSION_NOTE_SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_exact_current_binding_and_scalar_v1_are_preserved(self):
        self.assertEqual(generate.SESSION_NOTE_OUTPUT.read_text(), generate.render_session_note(self.source))
        for path, expected in {
            'idl/ev.app.private-data.v1.json': '0378f19e50bbcaee1ff695a52c3bdff7eb00a616d644c9a11d382f1e80cb87d9',
            'tools/idl/app_data.rs.in': '067506c5d99a7fc9b5cd4bdc6933d155f73c233801a27ecd0ecb266bc87bf7e9',
            'libs/userspace-contract/src/app_data.rs': 'bcc60422c2be1c04675f5686c10aae7d184a835a873b7e5633ae58537879a215',
        }.items():
            self.assertEqual(hashlib.sha256((generate.ROOT / path).read_bytes()).hexdigest(), expected)
        with self.assertRaises(ValueError):
            generate.render_app_data(self.source)
        with self.assertRaises(ValueError):
            generate.render_session_note(generate.APP_DATA_SOURCE.read_bytes())

    def test_authority_cas_credit_and_quarantine_semantics_cannot_be_dropped(self):
        replacements = [
            (('version',), True), (('wire','bytes'), 16), (('wire','magic'), 'ND'),
            (('wire','nonce'), 'wrapping_u32'), (('wire','requests','Read'), 2),
            (('wire','refusal_base'), 0), (('bulk','bytes'), 512),
            (('bulk','codec'), 'scalar_v1'), (('bulk','write'), 'unchecked_overwrite'),
            (('bulk','checksum'), 'authentication'),
            (('transport','max_capabilities'), 1),
            (('transport','max_outstanding_per_actual_incarnation'), 2),
            (('transport','retry'), 'retry_accepted'),
            (('transport','completion'), 'send_acceptance'),
            (('transport','shared_page'), 'reuse_after_timeout'),
            (('transport','authority'), 'AppId_from_wire'),
        ]
        for path, replacement in replacements:
            value = copy.deepcopy(self.value)
            field = value
            for name in path[:-1]:
                field = field[name]
            field[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate.render_session_note(json.dumps(value).encode())

    def test_last_invalid_schema_cannot_partially_rewrite_any_earlier_binding(self):
        for source in [b'{}', b'[]', b'null', self.source + b'{}',
                       self.source.replace(b'"schema": 1,', b'"schema": 1, "schema": 1,')]:
            with self.assertRaises(ValueError):
                generate.render_session_note(source)
        parent = generate.ROOT / 'build/test-tmp'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            directory = Path(directory)
            bad = directory / 'bad.json'
            bad.write_text('{}')
            names = ['OUTPUT', 'CAP_OUTPUT', 'PROVIDER_OUTPUT', 'APP_DATA_OUTPUT', 'SESSION_NOTE_OUTPUT']
            outputs = []
            for name in names:
                path = directory / (name + '.rs')
                path.write_text('preserved-' + name)
                outputs.append(path)
            before = [path.read_bytes() for path in outputs]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(generate, 'SESSION_NOTE_SOURCE', bad))
                stack.enter_context(patch('sys.argv', ['generate.py']))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                for name, path in zip(names, outputs):
                    stack.enter_context(patch.object(generate, name, path))
                self.assertEqual(generate.main(), 1)
            self.assertEqual([path.read_bytes() for path in outputs], before)


if __name__ == '__main__':
    unittest.main()
