#!/usr/bin/env python3
"""Live shared-map revocation with exact CPL3 stale-address fault checks."""
import re
import sys
import bootstrap
import jobs

RECORD = 'status=PASS invalidated=3 denied=3 faults=3 sibling_live=true'


def verify_revocation(evidence, runs, positive=True, cpus=1):
    records = jobs.verify_jobs(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_REVOKE (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed live mapping revocation proof')
        if positive:
            records[index - 1]['live_revocation'] = dict(invalidated=3, denied=3,
                faults=3, sibling_live=True, cpu='BSP', remote_shootdown=False)
    return records


def extra_checks(run, checks):
    jobs.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_revocation(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_revocation
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-05b', 'revocation',
        'BSP controller returns to a retained root on every trap and validates live mapping leases before dispatch. Closed/revoked authority removes the leaf before user resumption. Three successful user revocations trigger exact CPL3 nonpresent faults at stale shared addresses, deny remapping, and preserve sibling grants. No remote TLB shootdown or public process loader.',
        sources, extra_checks=extra_checks))
