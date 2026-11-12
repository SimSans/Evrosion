"""Closed generated provider contract: compatibility and refusal regressions."""
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


class ProviderGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.source = generate.PROVIDER_SOURCE.read_bytes()
        self.value = json.loads(self.source)

    def test_exact_generated_binding_and_legacy_outputs_are_independent(self):
        self.assertEqual(generate.PROVIDER_OUTPUT.read_text(), generate.render_provider(self.source))
        self.assertEqual(generate.OUTPUT.read_text(), generate.render(generate.SOURCE.read_bytes()))
        self.assertEqual(generate.CAP_OUTPUT.read_text(), generate.render_cap(generate.CAP_SOURCE.read_bytes()))
        # Adding the provider must not rewrite either pre-existing contract.
        legacy_sha256 = {'echo': '51f02789437824da3a6e3cc25b54b08c684eaa41e4fecd3c01f4dac7597aefa9', 'cap_echo': 'f46792d695d0f252029aa757745879b62f5311e6901fe33b02a820ed48556006'}
        for name, expected in legacy_sha256.items():
            path = generate.ROOT / f'libs/userspace-contract/src/{name}.rs'
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
        self.assertIn(hashlib.sha256(self.source).hexdigest(), generate.PROVIDER_OUTPUT.read_text())

    def test_required_semantics_types_bounds_and_refusals_cannot_silently_change(self):
        cases = [
            (('schema',), True), (('version',), 2), (('interface',), 'ev.test.echo'),
            (('maturity',), 'Stable'), (('wire', 'bytes'), 16),
            (('wire', 'endianness'), 'big'), (('wire', 'payload', 'type'), 'pointer'),
            (('wire', 'refusal_opcode'), 2), (('operation', 'semantics'), 'MUTATING'),
            (('operation', 'input_max'), 4294967295),
            (('operation', 'reply'), 'unchecked_twice_value_plus_one'),
            (('operation', 'refusals', 'overflow'), True),
            (('transport', 'max_capabilities'), 1),
            (('transport', 'max_messages'), 0),
            (('transport', 'synchronous', 'max_accepted_requests'), 2),
            (('transport', 'synchronous', 'reentrancy'), 'allowed'),
            (('transport', 'synchronous', 'deadline'), 'none'),
            (('transport', 'synchronous', 'timeout'), 'proof_of_nonexecution'),
        ]
        for path, replacement in cases:
            value = copy.deepcopy(self.value)
            field = value
            for name in path[:-1]:
                field = field[name]
            field[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate.render_provider(json.dumps(value).encode())

    def test_missing_unknown_duplicate_wrong_contract_and_trailing_data_fail_closed(self):
        bad = [b'{}', b'[]', b'null', b'broken', self.source + b'{}',
               self.source.replace(b'"schema": 1,', b'"schema": 1, "schema": 1,'),
               self.source.replace(b'"overflow": 2', b'"overflow": 2, "overflow": 2'),
               generate.SOURCE.read_bytes(), generate.CAP_SOURCE.read_bytes()]
        for source in bad:
            with self.subTest(source=source[:80]), self.assertRaises(ValueError):
                generate.render_provider(source)
        for mode in ['missing', 'unknown']:
            value = copy.deepcopy(self.value)
            if mode == 'missing':
                del value['operation']['input_max']
            else:
                value['operation']['ignored_authority'] = 'global-provider'
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                generate.render_provider(json.dumps(value).encode())

    def test_bad_third_contract_does_not_partially_update_any_output(self):
        # Failure probes stay under ignored repository scratch, never sources.
        scratch = generate.ROOT / 'build/test-tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            directory = Path(directory)
            bad = directory / 'bad.json'
            bad.write_text('{}')
            outputs = [directory / name for name in ['echo.rs', 'cap_echo.rs', 'provider.rs']]
            for index, output in enumerate(outputs):
                output.write_text(f'preserve-{index}')
            before = [path.read_bytes() for path in outputs]
            with patch.object(generate, 'PROVIDER_SOURCE', bad), \
                 patch.object(generate, 'OUTPUT', outputs[0]), \
                 patch.object(generate, 'CAP_OUTPUT', outputs[1]), \
                 patch.object(generate, 'PROVIDER_OUTPUT', outputs[2]), \
                 patch('sys.argv', ['generate.py']), \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(generate.main(), 1)
            self.assertEqual([path.read_bytes() for path in outputs], before)


if __name__ == '__main__':
    unittest.main()
