#!/usr/bin/env python3
"""Bounded, capability-routed actual user-process fault diagnostics."""
import re
import sys
import bootstrap
import extended

RECORD = 'status=PASS records=3 denied=3 consumed_once=true kernel_sender=true'


def verify_fault_delivery(evidence, runs, positive=True, cpus=1):
    records = extended.verify_extended(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_FAULT_DELIVERY (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed fault delivery proof')
        if positive:
            records[index - 1]['fault_delivery'] = dict(records=3, denied=3, consumed_once=True, kernel_sender=True)
    return records


def extra_checks(run, checks):
    extended.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_fault_delivery(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_fault_delivery
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-06e', 'fault-delivery',
        'Kernel-origin bounded fault records delivered to an authorized observer after process retirement. Actual user UD/PF/GP diagnostics checked once by surviving userspace, missing receive authority denied. Overflow/dead-observer never block containment. No service restart policy.',
        sources, extra_checks=extra_checks))
