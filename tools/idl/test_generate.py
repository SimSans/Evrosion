#!/usr/bin/env python3
"""Negative schema cases for the closed bootstrap IDL producer."""
import copy
import json
import unittest

import generate


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.source = generate.SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_checked_in_output_matches_exact_schema_and_generator(self):
        self.assertEqual(generate.OUTPUT.read_text(), generate.render(self.source))

    def test_unsupported_semantics_are_rejected_instead_of_silently_ignored(self):
        for path, replacement in [
            (('schema',), 2),
            (('version',), True),
            (('interface',), 'ev.test.other'),
            (('maturity',), 'Stable'),
            (('wire', 'bytes'), 16),
            (('wire', 'endianness'), 'big'),
            (('wire', 'response_opcode'), 1),
            (('wire', 'payload', 'type'), 'u64'),
            (('transport', 'modes'), ['unbounded_sync']),
            (('transport', 'max_messages'), 5),
            (('transport', 'max_capabilities'), 1),
            (('transport', 'deadline'), 'none'),
            (('transport', 'synchronous', 'max_accepted_requests'), 2),
            (('transport', 'synchronous', 'reentrancy'), 'allowed'),
            (('transport', 'synchronous', 'deadline'), 'none'),
            (('transport', 'synchronous', 'cancellation'), 'rollback_guaranteed'),
            (('transport', 'synchronous', 'timeout'), 'callee_did_not_execute'),
            (('operation', 'semantics'), 'NON_RETRYABLE'),
        ]:
            value = copy.deepcopy(self.value)
            field = value
            for name in path[:-1]:
                field = field[name]
            field[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate.render(json.dumps(value).encode())

    def test_missing_unknown_duplicate_fields_and_wrong_types_are_rejected(self):
        for bad in [
            b'{}', b'[]', b'null', b'not json',
            self.source.replace(b'"schema": 1,', b'"schema": 1, "schema": 1,'),
            self.source.replace(b'"type": "u32"', b'"type": "u32", "type": "u32"'),
        ]:
            with self.subTest(source=bad[:50]), self.assertRaises(ValueError):
                generate.render(bad)
        value = copy.deepcopy(self.value)
        value['transport']['ignored_future_field'] = 'unsafe-to-ignore'
        with self.assertRaises(ValueError):
            generate.render(json.dumps(value).encode())
        del value['transport']
        with self.assertRaises(ValueError):
            generate.render(json.dumps(value).encode())


class CapabilityGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.source = generate.CAP_SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_exact_generated_cap_contract_and_legacy_bytes_are_independent(self):
        self.assertEqual(generate.CAP_OUTPUT.read_text(), generate.render_cap(self.source))
        self.assertEqual(generate.OUTPUT.read_text(), generate.render(generate.SOURCE.read_bytes()))
        with self.assertRaises(ValueError):
            generate.render(self.source)
        with self.assertRaises(ValueError):
            generate.render_cap(generate.SOURCE.read_bytes())

    def test_attachment_ownership_and_deadline_extensions_cannot_disappear(self):
        for path, replacement in [
            (('version',), True),
            (('interface',), 'ev.test.echo'),
            (('wire', 'magic'), 'EV'),
            (('wire', 'bytes'), 16),
            (('wire', 'payload', 'type'), 'u64'),
            (('attachment', 'count'), 0),
            (('attachment', 'count'), True),
            (('attachment', 'kind'), 'Endpoint'),
            (('attachment', 'rights'), ['READ']),
            (('attachment', 'rights'), ['READ', 'WRITE', 'TRANSFER']),
            (('attachment', 'rights'), ['READ', 'TRANSFER', 'TRANSFER']),
            (('attachment', 'ownership'), 'copy'),
            (('attachment', 'reply'), 'fresh_unrelated_object'),
            (('transport', 'modes'), ['bounded_async']),
            (('transport', 'max_capabilities'), 0),
            (('transport', 'max_messages'), 2),
            (('transport', 'synchronous', 'deadline'), 'none'),
            (('transport', 'synchronous', 'timeout'), 'guaranteed_refund'),
            (('transport', 'synchronous', 'ownership_outcomes'), ['status_boolean']),
        ]:
            value = copy.deepcopy(self.value)
            field = value
            for name in path[:-1]:
                field = field[name]
            field[path[-1]] = replacement
            with self.subTest(path=path, replacement=replacement), self.assertRaises(ValueError):
                generate.render_cap(json.dumps(value).encode())

    def test_missing_unknown_duplicate_and_wrong_typed_fields_fail_closed(self):
        for bad in [
            b'{}', b'[]', b'null', b'not json',
            self.source.replace(b'"schema": 1,', b'"schema": 1, "schema": 1,'),
            self.source.replace(b'"count": 1,', b'"count": 1, "count": 1,'),
        ]:
            with self.subTest(source=bad[:50]), self.assertRaises(ValueError):
                generate.render_cap(bad)
        for operation in ['missing', 'unknown']:
            value = copy.deepcopy(self.value)
            if operation == 'missing':
                del value['attachment']
            else:
                value['attachment']['silently_ignored'] = True
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                generate.render_cap(json.dumps(value).encode())


if __name__ == '__main__':
    unittest.main()
