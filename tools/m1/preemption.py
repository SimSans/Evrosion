#!/usr/bin/env python3
"""Timer preemption and finite masked-clock failure, with cumulative regressions."""
import json
import re
import sys
from pathlib import Path
import bootstrap
import threads


def verify_preemption(evidence, runs, positive=True, cpus=1):
    records = threads.verify_threads(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_PREEMPT (.+)\r?$', serial, re.MULTILINE)
        if len(lines) != (1 if positive else 0):
            raise RuntimeError('Missing/duplicate/unexpected preemption record')
        if not positive:
            continue
        match = re.fullmatch(r'status=PASS threads=2 quanta=(\d+) dispatches=(\d+) progress=true restored=true', lines[0].strip())
        if not match or not 8 <= int(match[1]) <= 64 or int(match[2]) != int(match[1]) + 2:
            raise RuntimeError('Invalid preemption proof or attribution counts')
        records[index - 1]['preemption'] = dict(threads=2, quanta=int(match[1]),
            dispatches=int(match[2]), progress=True, restored=True, cpu='BSP', userspace=False)
    return records


def extra_checks(run, checks):
    threads.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_preemption(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True
    run('preempt-stall-build', ['cargo', 'ev', 'build', '--fixture', 'preempt-stall'])
    text = run('preempt-stall', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Masked-clock fixture did not identify evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1 or result['runs'][0]['exit_status'] != 35
        or serial.count('message=M1 deliberate masked preemption clock: finite work bound reached') != 1
        or serial.count('EVROSION_PANIC ') != 1 or 'EVROSION_M1_PREEMPT status=PASS' in serial
        or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1
        or 'EVROSION_M0_RESULT status=PASS' in serial):
        raise RuntimeError('Masked clock did not fail with a finite worker bound')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
                     expected_failure='Masked IRQ0 causes finite 4096-iteration worker failure; QEMU exits 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_preemption
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-04c', 'preemption',
        'IRQ0 preempts two non-yielding kernel workers on BSP, both progress and exit. Timer tick and per-Job dispatch counts agree. No userspace/SMP scheduler, CPU-time budgets or general IRQ routing.',
        sources, extra_checks=extra_checks))
