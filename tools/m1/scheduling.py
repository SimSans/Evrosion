#!/usr/bin/env python3
"""Scheduler policy acceptance, explicitly distinct from context switching."""
import re
import sys
import bootstrap
import smp

RECORD = ('status=PASS scope=policy threads=2 jobs=2 dispatches=36 '
          'signal=true deadline=true stale_rejected=true')


def verify_scheduling(evidence, runs, positive=True, cpus=1):
    records = smp.verify_smp(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_SCHEDULER (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed scheduler policy proof')
        if positive:
            records[index - 1]['scheduler'] = dict(scope='policy', threads=2, jobs=2,
                dispatches=36, signal=True, deadline=True, stale_rejected=True,
                context_switching=False, preemption=False)
    return records


def extra_checks(run, checks):
    smp.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_scheduling(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_scheduling
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sys.exit(bootstrap.main('M1-04a', 'scheduling',
        'Bounded scheduler state transitions and Job dispatch attribution; BSP-executed policy proof only. No context switching, event queue, CPU-time budgets, preemption or SMP scheduling.',
        sources, extra_checks=extra_checks))
