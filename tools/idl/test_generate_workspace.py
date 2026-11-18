"""Unknown/duplicate/type/semantics and atomic generation boundaries."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate
import generate_workspace as closed


class WorkspaceGeneration(unittest.TestCase):
    def cases(self):
        return [(generate.WORKSPACE_SOURCE, generate.WORKSPACE_TEMPLATE, generate.WORKSPACE_OUTPUT, closed.WORKSPACE),
                (generate.FILE_V2_SOURCE, generate.FILE_V2_TEMPLATE, generate.FILE_V2_OUTPUT, closed.FILE_V2)]

    def test_exact_closed_schemas_reproduce_generated_bindings(self):
        for source, template, output, expected in self.cases():
            self.assertEqual(closed.render(source.read_bytes(), template.read_text(), expected), output.read_text())
        with self.assertRaises(ValueError):
            closed.schema(generate.FILE_V2_SOURCE.read_bytes(), closed.WORKSPACE)
        with self.assertRaises(ValueError):
            closed.schema((generate.ROOT / 'idl/ev.internal.file.v1.json').read_bytes(), closed.FILE_V2)

    def test_every_declared_field_is_required_and_unknown_fields_fail(self):
        def objects(value):
            if isinstance(value, dict):
                yield value
                for child in value.values():
                    yield from objects(child)
        for source, _, _, expected in self.cases():
            original = json.loads(source.read_bytes())
            for index in range(len(list(objects(original)))):
                value = copy.deepcopy(original)
                item = list(objects(value))[index]
                item['ignored_future_authority'] = 'ambient'
                with self.subTest(interface=expected['interface'], index=index), self.assertRaises(ValueError):
                    closed.schema(json.dumps(value).encode(), expected)
                for key in list(list(objects(original))[index]):
                    value = copy.deepcopy(original)
                    del list(objects(value))[index][key]
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        closed.schema(json.dumps(value).encode(), expected)

    def test_integer_bool_float_duplicate_and_malformed_values_are_not_equivalent(self):
        def leaves(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from leaves(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from leaves(child, path + (index,))
            else:
                yield path, value
        for source, _, _, expected in self.cases():
            original = json.loads(source.read_bytes())
            for path, leaf in leaves(original):
                replacements = [None]
                if type(leaf) is int:
                    replacements += [True, float(leaf)]
                elif type(leaf) is bool:
                    replacements += [int(leaf), not leaf]
                elif isinstance(leaf, str):
                    replacements += [leaf + '_silently_changed']
                for replacement in replacements:
                    value = copy.deepcopy(original)
                    item = value
                    for key in path[:-1]:
                        item = item[key]
                    item[path[-1]] = replacement
                    with self.subTest(path=path, value=replacement), self.assertRaises(ValueError):
                        closed.schema(json.dumps(value).encode(), expected)
            source_bytes = source.read_bytes()
            duplicate = source_bytes.replace(b'"control_bytes": 256', b'"control_bytes": 256, "control_bytes": 256')
            for bad in [b'{}', b'[]', b'null', b'not-json', duplicate, source_bytes.replace(b'"schema": 1', b'"schema": 1, "schema": 1')]:
                with self.assertRaises(ValueError):
                    closed.schema(bad, expected)

    def test_invalid_last_schema_cannot_partially_publish_any_binding(self):
        names = ['OUTPUT', 'CAP_OUTPUT', 'PROVIDER_OUTPUT', 'APP_DATA_OUTPUT',
                 'SESSION_NOTE_OUTPUT', 'DOCUMENT_OUTPUT', 'DOCUMENT_CONTROL_OUTPUT',
                 'FOCUSED_INPUT_OUTPUT', 'DOCUMENT_TEST_OUTPUT', 'WORKSPACE_OUTPUT', 'FILE_V2_OUTPUT']
        parent = generate.ROOT / 'build/test-tmp'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            directory = Path(directory)
            bad = directory / 'bad.json'; bad.write_text('{}')
            paths = [directory / (name + '.rs') for name in names]
            for name, path in zip(names, paths):
                path.write_text('preserved-' + name)
            before = [path.read_bytes() for path in paths]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(generate, 'FILE_V2_SOURCE', bad))
                stack.enter_context(patch('sys.argv', ['generate.py']))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                for name, path in zip(names, paths):
                    stack.enter_context(patch.object(generate, name, path))
                self.assertEqual(generate.main(), 1)
            self.assertEqual([path.read_bytes() for path in paths], before)


if __name__ == '__main__':
    unittest.main()
