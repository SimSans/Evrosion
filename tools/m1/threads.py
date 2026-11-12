#!/usr/bin/env python3
"""Real cooperative contexts plus deliberate saved-register corruption."""
import json
import re
import sys
from pathlib import Path
import bootstrap
import scheduling

RECORD = ('status=PASS threads=2 dispatches=36 switches=72 guards=4 '
          'registers=true stacks=true signal=true deadline=true exited=true')


def verify_threads(evidence, runs, positive=True, cpus=1):
    records = scheduling.verify_scheduling(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_THREADS (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed context-switch proof')
        if positive:
            records[index - 1]['threads'] = dict(threads=2, dispatches=36,
                switches=72, guards=4, registers=True, stacks=True,
                signal=True, deadline=True, exited=True, preemption=False)
    return records


def extra_checks(run, checks):
    scheduling.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_threads(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True
    run('context-corruption-build', ['cargo', 'ev', 'build', '--fixture', 'context-corruption'])
    text = run('context-corruption', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Context-corruption fixture did not identify evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1 or result['runs'][0]['exit_status'] != 35
        or serial.count('message=M1 deliberate context corruption detected') != 1
        or serial.count('EVROSION_PANIC ') != 1 or 'EVROSION_M1_THREADS status=PASS' in serial
        or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1
        or 'EVROSION_M0_RESULT status=PASS' in serial):
        raise RuntimeError('Saved-register corruption was not detected by the resumed thread')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
                     expected_failure='Corrupted saved r12 detected after resume; QEMU exits 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_threads
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-04b', 'threads',
        'Two cooperative kernel contexts with guarded private stacks, callee-saved register probes, signal/deadline resumption and Job dispatch attribution. No preemption, user scheduling, SMP scheduling or CPU-time budgets.',
        sources, extra_checks=extra_checks))
