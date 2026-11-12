#!/usr/bin/env python3
"""Exact hardware protection-fault acceptance, plus prior M1 regressions."""
import re
import sys
import json
from pathlib import Path
import bootstrap
import paging


def verify_faults(evidence, runs, positive=True):
    records = paging.verify_paging(evidence, runs, positive)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        matches = re.findall(r'^EVROSION_M1_FAULTS status=PASS readonly=true noexecute=true '
                             r'unmapped=true recovered=3\r?$', serial, re.MULTILINE)
        if len(matches) != (1 if positive else 0):
            raise RuntimeError('Missing, duplicate or unexpected protection-fault proof')
        if positive:
            records[index - 1]['faults'] = {'readonly': True, 'noexecute': True,
                                            'unmapped': True, 'recovered': 3}
    return records


def unexpected_exception(run, checks):
    run('exception-build', ['cargo', 'ev', 'build', '--fixture', 'exception'])
    text = run('unexpected-exception', ['cargo', 'ev', 'test', 'boot', '--runs', '1'], expected_exit=1)
    checks[-1]['passed'] = False
    paths = re.findall(r'^Evidence: (.+)$', text, re.MULTILINE)
    if len(paths) != 1:
        raise RuntimeError('Unexpected-exception test did not identify evidence')
    evidence = Path(paths[0]).resolve()
    if not evidence.is_relative_to(bootstrap.ROOT / 'build/m0/evidence'):
        raise RuntimeError('Unexpected-exception evidence escaped repository')
    result = json.loads((evidence / 'results.json').read_text())
    serial = (evidence / 'run-001/serial.log').read_text()
    if (result['passed'] or len(result['runs']) != 1
            or result['runs'][0]['exit_status'] != 35
            or len(re.findall(r'^EVROSION_EXCEPTION vector=6 error=0x0 rip=0x[0-9a-f]+ '
                              r'address=0x[0-9a-f]+\r?$', serial, re.MULTILINE)) != 1
            or serial.count('EVROSION_M0_RESULT status=FAIL code=1') != 1
            or 'EVROSION_M0_RESULT status=PASS' in serial or 'EVROSION_M1_FAULTS' in serial):
        raise RuntimeError('Unexpected exception did not fail closed with a bounded diagnostic')
    checks[-1].update(passed=True, evidence=str((evidence / 'results.json').relative_to(bootstrap.ROOT)),
                      expected_failure='Unarmed #UD reports vector 6 and exits QEMU with status 35')


if __name__ == '__main__':
    bootstrap.verify_boot = verify_faults
    sys.exit(bootstrap.main('M1-03a', 'faults',
        'Owned exception entry and exact supervisor protection probes. User fault containment, IRQs, timers and SMP are pending.',
        ['kernel/src/mapping.rs', 'kernel/src/paging.rs', 'kernel/src/exception.rs',
         'kernel/src/traps.rs', 'kernel/src/traps.S', 'kernel/Cargo.toml',
         'tools/ev/src/cli.rs', 'tools/ev/src/build.rs', 'tools/m1/paging.py', 'tools/m1/faults.py'],
        extra_checks=unexpected_exception))
