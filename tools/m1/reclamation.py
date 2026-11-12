#!/usr/bin/env python3
"""Quiescent user-root teardown, scrubbed frame reuse and active-root rejection."""
import json
import re
import sys
from pathlib import Path
import bootstrap
import retirement


def verify_reclamation(evidence, runs, positive=True, cpus=1):
    records = retirement.verify_retirement(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_RECLAIM (.+)\r?$', serial, re.MULTILINE)
        if len(lines) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected reclamation proof')
        if not positive:
            continue
        match = re.fullmatch(r'status=PASS frames=42 reused=(\d+) zeroed=true restored=true', lines[0].strip())
        if not match or not 28 <= int(match[1]) <= 42:
            raise RuntimeError('Invalid frame reuse counts or scrubbing proof')
        records[index - 1]['retirement']['physical_reuse'] = True
        records[index - 1]['reclamation'] = dict(frames=42, reused=int(match[1]),
            zeroed=True, restored=True, cpu='BSP', shared_memory=False)
    return records


def extra_checks(run, checks):
    retirement.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_reclamation(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True
    run('reclaim-active-root-build', ['cargo', 'ev', 'build', '--fixture', 'reclaim-active-root'])
    text = run('reclaim-active-root', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Active-root fixture did not identify evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1 or result['runs'][0]['exit_status'] != 35
            or serial.count('cannot reclaim active user root') != 1
            or serial.count('EVROSION_PANIC ') != 1
            or serial.count('EVROSION_M1_IPC status=PASS') != 1
            or 'EVROSION_M1_RECLAIM status=PASS' in serial
            or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1
            or 'EVROSION_M0_RESULT status=PASS' in serial):
        raise RuntimeError('Active user root was not rejected before reclamation')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
        expected_failure='Active CR3 guard rejects reclamation before touching any owned page; QEMU exits 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_reclamation
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-02c', 'reclamation',
        'Inactive private user roots surrender owned data/table frames after process retirement; frames are scrubbed and recycled with allocator provenance, bounded metadata and count preservation. Six actual CPL3 contexts reuse physical storage. Active-root reclamation fails closed. No shared Memory Objects, remote TLB shootdown or general heap.',
        sources, extra_checks=extra_checks))
