#!/usr/bin/env python3
"""Quiescent process retirement and peer-death escrow cleanup."""
import re
import sys
import bootstrap
import waits

RECORD = 'status=PASS processes=6 reclaimed=3 discarded=3 closed=true quiescent=true'


def verify_retirement(evidence, runs, positive=True, cpus=1):
    records = waits.verify_waits(evidence, runs, positive, cpus)
    for index in range(1, runs + 1):
        serial = (evidence / f'run-{index:03}/serial.log').read_text()
        lines = re.findall(r'^EVROSION_M1_RETIRE (.+)\r?$', serial, re.MULTILINE)
        if [line.strip() for line in lines] != ([RECORD] if positive else []):
            raise RuntimeError('Missing, duplicate or malformed process retirement proof')
        if positive:
            records[index - 1]['retirement'] = dict(processes=6, reclaimed=3,
                discarded=3, closed=True, quiescent=True, physical_reuse=False)
    return records


def extra_checks(run, checks):
    waits.extra_checks(run, checks)
    for check in checks:
        if check['name'] == 'two-cpu-topology':
            check['passed'] = False
            check['bootstrap_records'] = verify_retirement(
                (bootstrap.ROOT / check['evidence']).parent, 3, cpus=2)
            check['passed'] = True


if __name__ == '__main__':
    bootstrap.verify_boot = verify_retirement
    sources = [str(p.relative_to(bootstrap.ROOT)) for p in
               sorted((bootstrap.ROOT / 'kernel/src').glob('*')) if p.is_file()]
    sources += [str(p.relative_to(bootstrap.ROOT)) for p in
                sorted((bootstrap.ROOT / 'tools/m1').glob('*.py'))]
    sources += ['kernel/Cargo.toml', 'tools/ev/src/build.rs', 'tools/ev/src/cli.rs']
    sys.exit(bootstrap.main('M1-06d', 'retirement',
        'Process retirement rejects active CPU runners, cancels ready/blocked siblings, closes capability domains without revoking transferred grants, returns escrow after actual receiver faults, and discards both-dead or expired orphan messages. Private frames and object/node metadata remain retained.',
        sources, extra_checks=extra_checks))
