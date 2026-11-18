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


class DocumentControlGeneration(unittest.TestCase):
    def setUp(self):
        self.source = generate.DOCUMENT_CONTROL_SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_binding_and_old_note_schema_keep_distinct_meanings(self):
        self.assertEqual(generate.DOCUMENT_CONTROL_OUTPUT.read_text(), generate.render_document_control(self.source))
        with self.assertRaises(ValueError):
            generate.render_document_control(generate.SESSION_NOTE_SOURCE.read_bytes())
        with self.assertRaises(ValueError):
            generate.render_session_note(self.source)

    def test_access_capability_nonce_and_shared_frame_rules_cannot_be_dropped(self):
        for path, replacement in [
            (('version',), True), (('wire', 'bytes'), 16),
            (('wire', 'requests', 'OpenRead'), 2), (('wire', 'nonce'), 'wrapping'),
            (('wire', 'grant_access_high_nibble', 'Edit'), 1),
            (('transport', 'request_reply_capabilities'), 1),
            (('transport', 'grant_capabilities'), 0),
            (('transport', 'grant_authority'), 'wire_access_bit'),
            (('transport', 'publish_completion'), 'send_success'),
            (('transport', 'publish_timeout'), 'reuse_frame'),
            (('transport', 'open_completion'), 'any_ack'),
            (('transport', 'consent'), 'old_read_approval'),
            (('transport', 'persistence'), 'serialize_handle'),
        ]:
            value = copy.deepcopy(self.value)
            field = value
            for name in path[:-1]:
                field = field[name]
            field[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate.render_document_control(json.dumps(value).encode())

    def test_invalid_last_control_schema_cannot_partially_update_other_interfaces(self):
        parent = generate.ROOT / 'build/test-tmp'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as name:
            directory = Path(name)
            bad = directory / 'bad.json'
            bad.write_text('{}')
            names = ['OUTPUT', 'CAP_OUTPUT', 'PROVIDER_OUTPUT', 'APP_DATA_OUTPUT',
                     'SESSION_NOTE_OUTPUT', 'DOCUMENT_OUTPUT', 'DOCUMENT_CONTROL_OUTPUT']
            paths = [directory / (name + '.rs') for name in names]
            for name, path in zip(names, paths):
                path.write_text('preserved-' + name)
            before = [path.read_bytes() for path in paths]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(generate, 'DOCUMENT_CONTROL_SOURCE', bad))
                stack.enter_context(patch('sys.argv', ['generate.py']))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                for name, path in zip(names, paths):
                    stack.enter_context(patch.object(generate, name, path))
                self.assertEqual(generate.main(), 1)
            self.assertEqual([path.read_bytes() for path in paths], before)


if __name__ == '__main__':
    unittest.main()
