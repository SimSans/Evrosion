"""Portable validator adversaries; no builds, VM execution or hardware claims."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import persistence as suite


def record(kind, sequence, related, body, version=2):
    out = bytearray(512)
    out[:8] = b'EVSTORE1'
    out[8:10] = version.to_bytes(2, 'little')
    out[10] = kind
    out[16:24] = sequence.to_bytes(8, 'little')
    out[24:32] = related.to_bytes(8, 'little')
    out[32:34] = len(body).to_bytes(2, 'little')
    out[64:64 + len(body)] = body
    out[480:] = hashlib.sha256(out[:480]).digest()
    return out


def image(version=2):
    data = bytearray(suite.DISK_BYTES)
    manifest = bytes(range(192))
    payload = b'owner-data-A'
    root = bytearray(384)
    root[1:6] = bytes((2, 1, 2, 0, 3))
    root[8:16] = (1).to_bytes(8, 'little')
    root[16:24] = (1).to_bytes(8, 'little')
    root[24:56] = hashlib.sha256(manifest).digest()
    root[56:88] = bytes((0x22,)) * 32
    root[88:90] = (192).to_bytes(2, 'little')
    root[176:178] = len(payload).to_bytes(2, 'little')
    root[184:192] = (1).to_bytes(8, 'little')
    root[192:224] = hashlib.sha256(payload).digest()
    for lba, block in [(16, record(1, 1, 0, root, version)),
                       (26, record(2, 1, 0, manifest, version)),
                       (28, record(3, 1, 1, payload, version))]:
        data[lba * 512:(lba + 1) * 512] = block
    return data


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        parent = suite.ROOT / 'build/test-tmp'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent, prefix='m3-validator-')
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_current_format_checksum_and_referenced_payload_are_required(self):
        good = image()
        state = suite.store_state(good)
        self.assertEqual((state['operation'], state['sequence'], state['known_good']), (0, 1, None))
        self.assertEqual(state['payload'], b'owner-data-A')
        for bad in [image(1), image(3), good[:16 * 512]]:
            with self.assertRaises(ValueError):
                suite.store_state(bad)
        bad = bytearray(good)
        bad[28 * 512 + 70] ^= 1
        with self.assertRaises(ValueError):
            suite.store_state(bad)
        self.assertEqual(suite.store_state(good)['payload'], b'owner-data-A')

    def test_pass_boolean_cannot_hide_a_recorded_failure(self):
        self.assertTrue(suite.passed({'passed':True,'error':None}))
        for key in ['error','capture_error','seal_error','validation_error','boot_link_error']:
            self.assertFalse(suite.passed({'passed':True,key:'actual retained failure'}))
        self.assertFalse(suite.passed({'passed':False}))

    def test_budget_diagnostics_require_actual_bounded_balanced_numeric_fields(self):
        good = dict(elapsed_ticks=1600, cpu_driver=1000, cpu_client=500,
                    cpu_critical=100, cpu_parent=1600, transitions=200, max_pending=1)
        self.assertEqual(suite.budget_record(good), good)
        for key, value in [('elapsed_ticks',2048),('cpu_parent',1599),('cpu_client',501),
                           ('transitions',0),('transitions',100001),('max_pending',2),
                           ('cpu_critical',-1),('cpu_driver',True)]:
            with self.assertRaises(ValueError):
                suite.budget_record({**good,key:value})
        with self.assertRaises(ValueError):
            suite.budget_record({key:value for key,value in good.items() if key!='cpu_driver'})

    def test_canonical_reserved_bytes_and_lengths_cannot_be_resealed_to_bypass(self):
        good = record(3, 1, 1, b'complete')
        for offset in [11, 15, 34, 63, 79, 479]:
            bad = bytearray(good)
            bad[offset] = 1
            bad[480:] = hashlib.sha256(bad[:480]).digest()
            with self.assertRaises(ValueError):
                suite.read_record(bad, 3)
        bad = bytearray(good)
        bad[32:34] = (417).to_bytes(2, 'little')
        bad[480:] = hashlib.sha256(bad[:480]).digest()
        with self.assertRaises(ValueError):
            suite.read_record(bad, 3)

    def test_source_match_is_exact_for_code_but_explicitly_scopes_docs_and_validator(self):
        rows = [{'path': 'kernel/src/main.rs', 'sha256': 'a' * 64},
                {'path': 'docs/status/state.json', 'sha256': 'b' * 64},
                {'path': 'tools/m3/persistence.py', 'sha256': 'c' * 64}]
        current = {'kernel/src/main.rs': 'a' * 64}
        suite.source_match({'source_inputs': rows}, current)
        for bad in [{}, {'kernel/src/main.rs': 'd' * 64},
                    {**current, 'services/new/src/main.rs': 'e' * 64}]:
            with self.assertRaises(ValueError):
                suite.source_match({'source_inputs': rows}, bad)
        with self.assertRaises(ValueError):
            suite.source_match({'source_inputs': rows + [rows[0]]}, current)
        for name in ['', '/outside', '../escape']:
            with self.assertRaises(ValueError):
                suite.code_path(name)

    def test_hashed_links_cannot_escape_or_silently_accept_changed_bytes(self):
        path = self.base / 'snapshot.raw'
        path.write_bytes(b'captured bytes')
        row = {'path': path.name, 'sha256': suite.sha(path.read_bytes())}
        self.assertEqual(suite.link(self.base, row), path)
        for name in ['../outside', '/outside']:
            with self.assertRaises(ValueError):
                suite.link(self.base, {**row, 'path': name})
        path.write_bytes(b'changed bytes')
        with self.assertRaises(ValueError):
            suite.link(self.base, row)
        self.assertEqual(path.read_bytes(), b'changed bytes')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink support')
    def test_symlink_including_a_symlink_base_is_refused(self):
        real = self.base / 'real'
        real.mkdir()
        (real / 'data').write_bytes(b'retained')
        alias = self.base / 'alias'
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            suite.bounded('alias/data', self.base)
        with self.assertRaises(ValueError):
            suite.bounded('data', alias)

    def test_guest_guards_and_host_control_changes_are_separate(self):
        before = image()
        for sector in [0, 1, 2, 15, 30, 8191]:
            after = bytearray(before)
            after[sector * 512] ^= 1
            with self.assertRaises(ValueError):
                suite.guards(before, after)
        changed = bytearray(before)
        changed[16 * 512 + 50] ^= 1
        suite.guards(before, changed)
        with self.assertRaises(ValueError):
            suite.control_change(before, changed)
        control = bytearray(before)
        control[2 * 512] = 1
        suite.control_change(before, control)
        with self.assertRaises(ValueError):
            suite.guards(before, before[:-1])

    def test_latest_failed_experiment_does_not_fall_back_to_an_older_pass(self):
        parent = self.base / 'build/m3/evidence'
        for index, passed in [(1, True), (2, False)]:
            folder = parent / f'generation-{index}'
            folder.mkdir(parents=True)
            path = folder / 'results.json'
            path.write_text(json.dumps({'kind': 'generation', 'passed': passed}))
            os.utime(path, ns=(index, index))
        with patch.object(suite, 'ROOT', self.base):
            selected = suite.latest('generation')
            self.assertEqual(selected.name, 'generation-2')
            with self.assertRaises(ValueError):
                suite.verify_workflow('generation', selected, {})
        self.assertEqual(json.loads((parent / 'generation-1/results.json').read_text())['passed'], True)
        self.assertEqual(json.loads((parent / 'generation-2/results.json').read_text())['passed'], False)

    def test_every_journal_case_final_snapshot_is_hash_checked_with_exact_order(self):
        names = ['initial', *(f'cut-{cut}' for cut in range(1, 7)), 'normal-commit']
        data = image()
        rows = []
        for name in names:
            directory = self.base / name
            directory.mkdir()
            snapshot = directory / 'data-final.raw'
            snapshot.write_bytes(data)
            record = {'path':snapshot.name,'sha256':suite.sha(data),'bytes':len(data),
                      'seed_sha256':suite.sha(data[:512]),'record_sha256':suite.sha(data[512:1024])}
            path = directory / 'case-result.json'
            path.write_text(json.dumps({'passed':True,'case':name,'final_disk':record}))
            rows.append({'path':str(path.relative_to(self.base)),'sha256':suite.sha(path.read_bytes())})
        result = {'cases':rows}
        self.assertEqual(set(suite.journal_case_snapshots(self.base,result)), set(names))
        reordered = {'cases':[rows[1],rows[0],*rows[2:]]}
        with self.assertRaises(ValueError):
            suite.journal_case_snapshots(self.base,reordered)
        damaged = self.base / 'cut-4/data-final.raw'
        changed = bytearray(data)
        changed[512] ^= 1
        damaged.write_bytes(changed)
        with self.assertRaises(ValueError):
            suite.journal_case_snapshots(self.base,result)


if __name__ == '__main__':
    unittest.main()
